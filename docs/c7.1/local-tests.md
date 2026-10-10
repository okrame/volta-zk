# C7.1 — test locali

[Design](design.md) · [Specifiche](specs.md) · [Sicurezza](security.md) ·
[Test su RunPod](runpod-tests.md) · [Evidenze storiche](../c7.1-history/evidence.md)

La [campagna H100 è conclusa](../c7.1-history/h100-campaign-close-2026-10-10.md),
con pod spento entro la deadline e zero certificati canonici. A04 termina per cap fisico dopo 86/512 gruppi, wall 780,205 s.
Prova/verifica complete e O=150/300 restano non verificati.

Le correzioni della campagna conservano [fallimenti e controlli](../c7.1-history/h100-canonical-06-2026-10-10.md)
nei record datati. Localmente passano 36 test del monitor, due test Python
dell'owner CUDA e i nove controlli documentali. Le regressioni Rust ridotte
coprono marker non selezionati/selezionati, entrambi gli errori di ruolo,
reader W con pagine grandi, codec cGGM e span del prefisso originale.
I timeout locali rimangono esiti negativi; i limiti sotto non cambiano.

Il [diagnostico A finale](../c7.1-history/h100-a-blocking-terminal-2026-10-10.md)
conserva lo stop fisico anche con lanci sincroni: 86/512 gruppi, nessun
certificato. I test finiti passati non sostituiscono il percorso completo.

La [regressione del prefisso](../c7.1-history/h100-prefix-candidate-2026-10-10.md)
fallisce prima della correzione e passa dopo sullo stesso binario della
fixture C++: sei test, 12 casi di span, rifiuti precedenti dell'owner,
radici/aperture/istogramma A e full wire/FS/MAC originali. La
[parità sm_90](../c7.1-history/h100-prefix-validation-2026-10-10.md) e quella
[con code ridotte](../../benchmarks/results/c71-h100-quarter-parity-2026-10-10-47af19bbe888.json),
anche [con lanci sincroni](../../benchmarks/results/c71-h100-blocking-parity-2026-10-10-47af19bbe888.json),
passano 15/15 test reali più controllo non lineare. Sono risultati del pod,
non test locali né prova completa. Il setup H100 con
[coda cGGM differita](../c7.1-history/h100-setup06-checkpoint-2026-10-10.md)
è completo; il raffinamento generale e l'accettazione canonica restano aperti.

La [chiusura locale del 10 ottobre](../c7.1-history/local-exploration-close-2026-10-10.md) registra le nuove verifiche locali e l'inventario dei
report/input effettivamente conservati; packed e tracce complete non
sono disponibili e non vengono scaricati. Gli 84,382 s della H100 sono
il nostro esecutore intero esatto: manca il confronto con un motore
ottimizzato sullo stesso workload. Il [piano hardware mirato](../c7.1-history/local-hardware-plan-2026-10-10.md) resta da eseguire soltanto
con una nuova autorizzazione hardware.

I controlli della nuova modifica mantengono esiti, limiti e provenienza:
`tests/test_c71_range_native.py` verifica riuso del flag, reset, capacità
trattenuta, transazioni sticky separate e fail-closed con driver simulato;
`tests/test_c71_temporary_ledger.py` verifica l'addebito fino al cleanup
e il setup AES reale con cache W/owner già installati;
`tests/test_c71_gamma_screen.py` verifica identità degli input e quattro
screening di scale A. Eseguire questi file separatamente, con 60 s /
AS 2 GiB, un worker e nessuna estensione automatica del timeout. Il filtro
Rust `c71_calibration_rms_program_screen_uses_original_compiler_and_rejects_bad_recipes`
confronta la CLI ridotta con il compilatore RMS originale e i suoi rifiuti.
Fixture, profili pubblici e tempi CPU non sono parità CUDA, qualità sui
pesi reali, ammissione Γ o previsione di accelerazione H100.

## Limiti e ambiente

I controlli locali usano input piccoli, un solo processo di test per volta,
un worker Rayon e 60 s / 2 GiB per invocazione. La compilazione è mirata,
con un solo job, 64 codegen unit, deadline 120 s e monitor del RSS
aggregato campionato: stop a 3 GiB. Il wrapper archiviato osserva i
processi visibili in `/proc`, esclusi sé stesso e i processi con PPid zero;
il valore può includere altri processi, non soltanto i figli della build.
Usa il target assoluto
`rust/target`, senza incremental. Il nuovo limite riguarda solo la build;
i timeout dei test non autorizzano estensioni.
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

Il wrapper seguente è quello della VM `/home/okrame/projects/volta-zk`;
contiene quel target assoluto. Su un altro host predisporre un wrapper
equivalente senza modificare l'artefatto storico. Log/report devono essere
nuovi: la directory temporanea distinta evita sovrascritture.

```bash
set -euo pipefail
C71_BUILD_MONITOR="$C71_ROOT/benchmarks/results/c71-crypto-rms-local-2026-10-09-abd2de09efb4/c71-build-monitor-120-20261009.py"
C71_BUILD_LOGS="$(mktemp -d /tmp/c71-build.XXXXXX)"
cd "$C71_ROOT/rust"
C71_RUST_HOST="$(rustc -vV | sed -n 's/^host: //p')"
C71_LLD_DIR="$(rustc --print sysroot)/lib/rustlib/$C71_RUST_HOST/bin/gcc-ld"
test -d "$C71_LLD_DIR"
python3 "$C71_BUILD_MONITOR" "$C71_BUILD_LOGS/lib.log" "$C71_BUILD_LOGS/lib.json" \
  cargo rustc --offline --locked -j 1 -p volta-pcs \
  --features c71-seed6-reference --lib --profile test \
  --config profile.dev.package.volta-pcs.opt-level=0 \
  --config profile.dev.package.volta-pcs.codegen-units=64 -- \
  -Clink-arg=-fuse-ld=lld "-Clink-arg=-B$C71_LLD_DIR" -Clink-arg=-Wl,--threads=1
python3 "$C71_BUILD_MONITOR" "$C71_BUILD_LOGS/calibration.log" "$C71_BUILD_LOGS/calibration.json" \
  cargo build --offline --locked -j 1 -p volta-pcs \
  --features c71-b12-pcs --example c71_calibration
python3 "$C71_BUILD_MONITOR" "$C71_BUILD_LOGS/reference.log" "$C71_BUILD_LOGS/reference.json" \
  cargo build --offline --locked -j 1 -p volta-pcs \
  --features c71-seed6-reference --example c71_canonical_reference
cd "$C71_ROOT"
```

Eseguire da `rust` per caricare `rust/.cargo/config.toml`: dipendenze O2,
crate test O0, 64 codegen unit nel comando mirato, un job, incremental disabilitato e
overflow checks conservati. `cargo rustc --lib --profile test` produce
il binario unit-test e applica gli argomenti finali al solo crate scelto
([Cargo](https://doc.rust-lang.org/cargo/commands/cargo-rustc.html)).
Il linker [LLD](https://lld.llvm.org/) è quello della toolchain già
installata, con un thread; il percorso deriva da sysroot/host, senza
dipendenze aggiunte o home del proprietario codificata nel comando.
La compilazione ha AS non limitato e deadline 120 s, separata dai test
AS 2 GiB/60 s. Il
[monitor archiviato](../../benchmarks/results/c71-crypto-rms-local-2026-10-09-abd2de09efb4/c71-build-monitor-120-20261009.py)
esegue il comando passato dopo log/report, osserva RSS aggregato e
arresta il gruppo a 3 GiB. Usarlo come wrapper: `timeout` da solo non
impone lo stop di memoria. Le impostazioni archiviate sono della VM locale.
La modifica operativa riduce i retry di build senza saturare la VM;
il precedente limite 60 s non era un requisito del protocollo.
I suoi timeout rimangono esiti storici immutabili nel
[checkpoint query](../c7.1-history/crypto-query-2026-10-09.md) e nel
[checkpoint RMS](../c7.1-history/crypto-rms-close-2026-10-09.md).
Non attribuire al riuso di una build il costo di una nuova compilazione.

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

Dopo la build mirata, eseguire **un filtro per invocazione**, con 60 s /
2 GiB AS e `--test-threads=1 --nocapture`. Le fixture native compilano
un driver CUDA simulato; confrontano matematica e lifecycle, senza
compilare/eseguire CUDA. I risultati datati, RSS e provenienza sono
nell'[indice delle evidenze](design.md#evidenze-e-decisioni).
Questi filtri costruiscono la libreria simulata anche su una H100:
`C71_NATIVE_PARITY_LIBRARY` non ne cambia il backend. I 14 ingressi
hardware espliciti e il range preesistente sono `#[ignore]`, elencati nel
[runbook](runpod-tests.md#parità-e-misure-rappresentative). Riutilizzano
gli stessi oracoli con Config esplicita e rifiutano la libreria simulata
anche rinominata. Fault injection e simboli mancanti rimangono host.
La preparazione locale verifica helper e guardie; l'esecuzione di quei
kernel richiede la campagna autorizzata.

| Filtro | Significato |
|---|---|
| `c71_canonical_device_` | Schedule dei 150 token nei tre contesti, tutti i producer, prefissi/checkpoint; scanner numerico su catena ridotta, senza W reale |
| `c71_canonical_resident` | Binding Arc/layout/runtime, originali, RNE e gather |
| `c71_b12_windowed_native_original_staging` | Staging di soli originali inizializzati, fence e span |
| `c71_b12_windowed_native_shared` | Range condiviso sui MAC originali e stesso owner |
| `c71_b12_windowed_native_byte` | Byte/gather e codec originali |
| `c71_b12_windowed_native_signed` | Range signed su originali |
| `c71_b12_windowed_native_failure` | Errori terminali e assenza di fallback |
| `c71_canonical_metrics_` | Wall/traffico/census, senza sommare picchi |
| `c71_canonical_runner_` | Selezione backend, verifica/promozione e journal |
| `c71_b12_native_hardware_parity_rejects_missing_and_host_library` | Libreria mancante/relativa/simulata, anche rinominata, e arena invalida rifiutate prima dell'owner CUDA |
| `c71_canonical_runner_diagnostic_timeout_and_disconnect` | Timeout finito esplicito, lettura bloccata e disconnessione terminali; socketpair locale |

Le socketpair locali possono richiedere un'eccezione al sandbox; non
usano rete esterna. Conservare il rifiuto sandbox e la successiva
esecuzione separatamente. Norm finale ha 149 righe: i test della schedule
non trasformano il batch in 150 per semplicità.

Il monitor della campagna ha fixture Python senza provider/GPU: lifecycle
W, limite congiunto, `smaps`, deadline/riserva, output esclusivi e privati,
errore GPU/cgroup e arresto dei gruppi figli. Eseguire sotto gli stessi
limiti locali. Le fixture emulano GPU, cgroup e `time`; processi,
sessioni/gruppi e lettura `smaps` sono locali reali:

```bash
(ulimit -v 2097152; timeout -k 5s 60s .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_c71_campaign_measure.py)
```

La [verifica pre-H100](../c7.1-history/crypto-preh100-operations-2026-10-09.md)
registra 28 test Rust, 28 test del monitor e 9 controlli documentali passati.
Le fixture non misurano HBM o picco fisico canonico. La
[procedura operativa](runpod-tests.md#preparazione-operativa-della-campagna)
distingue questi controlli dal futuro lancio H100.

Se il toolkit è disponibile, compilare libreria completa e diagnostico
senza eseguirli; altrimenti la build CUDA si svolge sul pod autorizzato:

```bash
nvcc -std=c++17 -O2 -arch=sm_90 --shared --cudart static -Xcompiler=-fPIC \
  cuda/c71_dense_i16.cu cuda/c71_range_native.cu cuda/c71_pcs_hash.cu \
  cuda/c71_pcs_weight.cu cuda/c71_pcs_weight_tensor.cu cuda/c71_pcs_source.cu \
  cuda/c71_pcs_salts.cu cuda/c71_pcs_query.cu cuda/c71_linear_native.cu \
  cuda/c71_pcs_residual.cu cuda/c71_pcs_residual_query.cu \
  cuda/c71_range_runtime.cpp \
  -o /tmp/libc71_device_runner.so
nvcc -std=c++17 -O2 -arch=sm_90 --cudart static \
  cuda/c71_nonlinear_parity.cu cuda/c71_dense_i16.cu -o /tmp/c71_device_parity
```

Il loader richiede tutti i simboli ABI4 correnti, comprese operazioni
sali, confronto Tensor, FFT naturale, cinque operazioni query iniziali,
quattro lineari e 19 nuove operazioni S1/contrazioni/Query E/hash paired.
Una libreria incompleta fallisce
prima dell'uso. Le FFT naturali sono definite nell'unità weight esistente.
L'unità lineare risolve i launcher dell'owner/caller ora verificato dal
[checkpoint lineare](../c7.1-history/crypto-linear-2026-10-09.md), distinto
dal precedente query. Le due unità residuali risolvono i launcher del
consumer S1 e Query E ora collegato; entrambe sono necessarie alla
linkline corrente. Conservare RSS/deadline della build separati e
nessun rapporto di speedup tra Rust O0 e C++ O2.

#### PCS iniziale, query e candidati

Ogni filtro della tabella si esegue separatamente. Evitare il prefisso
complessivo source: ora comprende Tree e prove composte e può superare
60 s. Tutti i confronti usano campi, sali/pad, root, byte del certificato,
transcript e MAC originali, secondo l'ambito indicato.

| Filtro | Significato |
|---|---|
| `c71_b12_native_incremental_hash_exact_roots_and_salt_bands` | Foglie di 128 colonne, sali a bande e tutti i livelli Merkle |
| `c71_b12_native_incremental_hash_coset_frontier_and_natural_root` | Ordine naturale/strided e frontier dei gruppi |
| `c71_b12_native_incremental_hash_rejections_and_fail_closed` | Tipo, ordine, copertura, owner, budget, launch/fence/aritmetica |
| `c71_b12_native_weight_columns_exact_signed_pads_fft_hash` | Tutte le word di 128 colonne/32 coset, contributi/pad, FFT e digest |
| `c71_b12_native_weight_rejections_and_fail_closed` | Guard accumuli W |
| `c71_b12_gemma_layout_matches_packed_addresses_and_physical_tensor_mles` | Mapping indirizzi packed e MLE fisiche |
| `c71_b12_native_weight_tree_exact_roots_openings_and_work` | Tree W col getter di produzione, root/aperture/lavoro |
| `c71_b12_native_weight_composed_full_chain_original_mac_and_transcript` | Prova completa ridotta, reference cache soltanto nella fixture |
| `c71_b12_native_weight_tree_fail_closed_without_scalar_fallback` | Tree W terminale senza getter/fallback su errore |
| `c71_b12_native_weight_geometry_and_resource_envelope` | Scansioni e risorse W, flag simultanei inclusi |
| `c71_b12_query_small_remainders_exact_fp3_and_cost` | Divisione monica, base/Fp3 e costo |
| `c71_b12_query_remainder` | Resti delle aperture |
| `c71_b12_query_split_zero_tail` | Split/padding senza getter del suffisso zero |
| `c71_b12_query_byte_windows_full_chain` | Finestre byte nella catena PCS |
| `c71_b12_native_source_four_cosets_fft_hash_original_bytes` | Tutte le 128 colonne su quattro coset, codec, pad/FFT/hash e istogramma |
| `c71_b12_native_source_pending_coverage_owner_and_failure` | Pending, copertura/span, owner e errori A |
| `c71_b12_native_source_geometry_and_resource_envelope` | Geometria A indipendente da W e conto simultaneo |
| `c71_b12_pcs_resident_source_tiles_original_biased_bytes` | Producer Affine/RNE→sink PCS senza download per riga |
| `c71_canonical_device_replay_original_rows_windows_and_failure` | Replay originale, finestre e terminalità |
| `c71_b12_range_window_permutation_and_intersections` | Permutazione e selezione finestre byte |
| `c71_b12_native_source_tree` | Tree A: root/aperture/istogramma/lavoro e guard terminali |
| `c71_b12_native_source_composed_full_chain_original_mac_and_transcript` | Prova composta A con reference cache solo nel test |
| `c71_canonical_device_original_scan_coverage_rejects_duplicate_and_omitted_rows` | Partizione unica delle emissioni A |
| `c71_b12_sourcewise_linear` | Coefficienti/endpoint/FS/MAC della closure a una scan per round |
| `c71_b12_original_scan_live_prefix_order_and_errors` | Ordine arbitrario, live/count, errori prima delle correlazioni |
| `c71_b12_native_weight_tensor` | Confronto ordinario/Tensor postFFT/hash sullo stesso owner, guard e simbolo obbligatorio |
| `c71_b12_native_pcs_compare_words` | Tutte le word canoniche, mismatch terminale e simbolo obbligatorio |
| `c71_b12_native_transform_natural_forward_inverse_and_work` | DFT Rust indipendente, log pari/dispari, inverse, segmenti batch e conto D2D |
| `c71_b12_native_transform_rejections_and_fail_closed` | Owner, tipo, span, alias, orientamento twiddle e errori terminali |
| `c71_b12_native_transform_symbols_are_mandatory` | Rifiuto di ciascun simbolo FFT mancante |
| `c71_b12_native_query_exact_horner_windows_pads_and_resources` | Resti iniziali A contro Horner, finestre identiche, suffissi vivi/pad e risorse |
| `c71_b12_native_query_reader_failure_without_host_fallback` | Reader unavailable/pending/foreign/errore terminale |
| `c71_b12_native_query_rejections_and_fail_closed` | Owner/tipo/span/alias e guard query |
| `c71_b12_native_query_private_phase_read_and_mandatory_symbols` | Letture private vietate e quattro simboli query obbligatori |
| `c71_b12_native_query_composed_uncached_chain_original_mac_and_transcript` | Catena D10 uncached, query iniziali native e commitment iniziale CPU; wire/FS/RNG, MAC originali e due verificatori |
| `c71_b12_native_weight_query_horner_signed_pads_duplicates_and_accounting` | 18 casi W originali sigillati, pad e ragged, ordine/duplicati, Horner, trasferimenti e retirement |
| `c71_b12_native_weight_query_symbol_is_mandatory` | Nuovo simbolo W assente: errore terminale |
| `c71_canonical_writer_fixed_capacity_preserves_wire_and_transcript` | Capacità canonica 96 MiB senza realloc, wire/FS esatti |

Il [checkpoint W/profilo](../c7.1-history/crypto-local-convergence-2026-10-09.md)
conserva anche la catena completa Seed6 AES fermata al limite locale
60 s sul binario O0, dopo l'eccezione per la sola socketpair Unix.
È un esito negativo; non ripeterla con limiti estesi. I precedenti positivi
restano validi nel proprio ambito, senza trasferire tempi a questo binario.
Il census di sorgente `python3 scripts/c71_residual_profile.py` usa solo
Git e ricevute pubbliche Γ; non esegue W, CUDA o provider. Mantiene le cinque
latenze canoniche mancanti e distingue sottoconti dai benchmark ridotti.

Per i sali eseguire separatamente i quattro filtri seguenti: il filtro
aggregato compila più fixture e si avvicina al limite 60 s.

```text
c71_b12_native_private_salts_owner_exact_stream_hash_and_work
c71_b12_native_private_salts_owner_metadata_alias_and_stale_capability
c71_b12_native_private_salts_owner_rejections_and_fail_closed
c71_b12_native_private_salts_owner_symbols_are_mandatory
```

Confrontano stream/offset/cap, tutti i digest e il consumo esatto, anche
attraverso due bande con un solo fence hash e zero upload sali. Ripetere
Tree W/A e prove composte dopo modifiche comuni dell'owner. Il prescan
del driver è sequenziale: non verifica prefix/scatter CUDA. Le letture
bounded della primitiva FFT sono esplicite e non cambiano il vincolo
senza D2H delle righe numeriche nel commitment iniziale.

Le prove composte D15 usano 16 MiB di righe iniziali nel riferimento
solo della fixture, conteggiati nel budget e assenti in produzione.
Getter effettivi sono verificati dai test Tree separati. I filtri
`c71_b12_native_weight_uncached_full_chain_performance_obligation` e
`c71_b12_native_source_uncached_full_chain_performance_obligation`
sono ignored dopo timeout a 60 s: non lanciarli con `--ignored` o limite
esteso, non contare skip come pass. Anche
`c71_b12_native_streaming_lookup_gkr_whir_positive_original_macs` supera
60 s sul binario O0 dell'ultimo checkpoint: il nome positivo non cambia
l'esito conservato. Anche
`c71_b12_native_composed_three_attempts_close_one_fs_and_promote_same_w_kv`
ha raggiunto 60 s dopo la correzione dei lifetime: il
[record distinto](../../benchmarks/results/c71-crypto-retirement-local-2026-10-09-96b69ded52c1.json)
conserva build/check dei claim e timeout, senza nuova parità composta.
I residui prestazionali si misurano sull'hardware autorizzato; questi
timeout conservano il proprio esito anche dopo le ottimizzazioni RMS.

Il [checkpoint RMS](../c7.1-history/crypto-rms-close-2026-10-09.md) usa
filtri separati, sempre AS 2 GiB/60 s e un thread. La nuova fixture
`c71_b12_packed_mixed_gkr_complete_wire_mac_and_endpoint` verifica GKR
senza PCS: 8 celle, 3 programmi, 2 depth, wire/FS/RNG/endpoint/MAC,
consumo esatto e rifiuto del MAC alterato. Non estende il credito PCS.
Il filtro `c71_ordinary_rms_packed_replay_mixed_nonzero_scales_exact_coefficients`
separa plan build da replay+row su scale nonzero, senza Γ ammesso.
`c71_b12_rms_cached_public_geometry_exact_mixed_recipes_and_contexts`
confronta cache e compilatore originale, chiavi, contesti e limiti.
Conservare i marker dei coefficienti del primo round, packed replay,
geometrie e metadati nel [record finale](../../benchmarks/results/c71-crypto-rms-local-2026-10-09-abd2de09efb4.json). I timeout
RMS c0 reale e mixed421 con PCS a 60 s sono negativi: nessun retry
con cap esteso sulla VM.

I controlli Python pertinenti si eseguono separatamente con gli stessi
limiti: `tests/test_c71_dense_i16.py`, `tests/test_c71_range_native.py`,
`tests/test_c71_pcs_tensor.py`, `tests/test_c71_attention_mma.py` e
`tests/test_c71_fft_microbench.py`. Verificano packing/frammenti/shuffle,
oracoli signed i128 indipendenti, modulo campo, padding e normalizzazione.
Attention verifica future KV/Pi già inizializzate con guard per lettura
ed i bound del bordo; conserva il finding precedente e la correzione in
record distinti. Le candidate attention restano non selezionate; Tensor W
è selezionato dopo la parità e il confronto H100, documentati nel design.
Questi test locali non compilano CUDA né provano scheduling/registri/spill hardware.

Il [diagnostico W](../../cuda/c71_pcs_weight_compare.cpp) può essere
compilato con g++ `-c` senza toolkit; non è linkato/eseguito localmente.
Con toolkit disponibile, compilare anche la candidata attention:

```bash
nvcc -std=c++17 -O2 -arch=sm_90 -c cuda/c71_attention_mma.cu -o /tmp/c71_attention_mma.o
```

La FFT e il caller delle query iniziali A sono integrati nel common owner
nel [checkpoint query](../c7.1-history/crypto-query-2026-10-09.md).
Il [checkpoint lineare](../c7.1-history/crypto-linear-2026-10-09.md)
verifica cinque filtri, da eseguire uno per invocazione:

| Filtro | Significato |
|---|---|
| `c71_b12_native_linear_original_codecs_exact_coefficients_endpoints_and_work` | 16 casi A/W, slack prodotto da argmax, i48 split, EQ/endpoint e zero tail senza letture |
| `c71_b12_native_linear_owner_token_coverage_and_fail_closed` | 30 rifiuti, token/owner privati, copertura, copie/fence/free e flag |
| `c71_b12_native_linear_symbols_are_required` | Quattro simboli ABI obbligatori assenti |
| `c71_b12_native_linear_producer_errors_burn_only_completed_rounds` | Cinque fault: correlazioni e FS avanzano solo per round completati |
| `c71_b12_native_linear_full_wire_fs_point_and_original_mac` | Prova D10 signed W esatta contro denso, PCS CPU, wire/FS/punto/MAC |

`tests/test_c71_linear_native.py` verifica 167 casi contro l'oracolo
denso e bench host D15/D17. I controlli S1 e Query E sono nel
[checkpoint integrato](../c7.1-history/crypto-residual-query-2026-10-09.md):

| Filtro | Significato |
|---|---|
| `c71_b12_native_residual_pcs_basis_is_distinct_and_canonical` | Base PCS distinta dai MAC e marshalling canonico |
| `c71_b12_native_residual_owner_coverage_private_tokens_and_faults` | Phase, owner, capacità, token, span/flag e terminalità |
| `c71_b12_native_residual_state_exact_coefficients_late_retention_and_views` | Singleton/OOD/contrazioni, retention tardiva, fold e viste storiche |
| `c71_b12_native_residual_paired_tree_root_salts_and_cpu_geometry` | Foglie da 12 limb, paired root, cursori e geometria CPU equivalente |
| `c71_b12_native_residual_query_horner_pads_duplicates_and_virtual_prefixes` | Query E contro Horner, cap piccoli, pad, ordine/duplicati, prefissi virtuali 0..2 e nessuna ricostruzione A |
| `c71_b12_native_residual_query_owner_final_values_and_faults` | Lineage root/child, triple finali, fasi private e failure terminali |
| `c71_b12_native_residual_query_full_whir_a_wire_fs_rng_and_original_mac` | Catena WHIR D10 A, query iniziali residenti, S1/query extension e wire/FS/RNG/MAC originali |
| `c71_b12_native_residual_query_full_whir_w_wire_fs_rng_and_original_mac` | Catena WHIR D10 W, iniziale CPU invariato, S1/query extension e wire/FS/RNG/MAC originali |

I 19 simboli nuovi si verificano con **un filtro per invocazione**, al
massimo quattro librerie mancanti in ciascun filtro:

```text
c71_b12_native_residual_symbols_1
c71_b12_native_residual_symbols_2
c71_b12_native_residual_symbols_3
c71_b12_native_residual_symbols_4
c71_b12_native_residual_query_symbols_1
c71_b12_native_residual_query_symbols_2
```

Non usare il prefisso residual complessivo: comprende catene e compilazioni
dinamiche separate. Applicare sempre AS 2 GiB/60 s ed un solo processo.
`tests/test_c71_pcs_residual.py` verifica matematica PCS e bench host;
`tests/test_c71_pcs_residual_query.py` verifica il loader a tre limb con
oracolo indipendente ed emulazione CTA, senza compilare/eseguire CUDA.
`tests/test_c71_pcs_short_hash.py` confronta foglie da 12 limb, nodi
paired e sali con BLAKE3 pinned; il
[record](../../benchmarks/results/c71-crypto-short-merkle-local-2026-10-09-d16870d8ff1b.json)
include le regressioni Rust dello stream e dell'owner sali, come componente
precedente. `tests/test_c71_range_native.py` verifica il common owner,
driver differito e lineage. Eseguire ciascun file Python separatamente.
Non aggregare i cinque filtri query
in una sola invocazione: ciascuno compila una fixture dinamica.
La futura parità sm_90, il tempo completo e il picco fisico si verificano
sulla H100 autorizzata. Non ridurre limiti query o aumentare implicitamente
ricostruzioni A per far passare fixture o conto memoria.

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

Le [evidenze datate](design.md#evidenze-e-decisioni) conservano anche
rifiuti sandbox, retry locali ed esiti negativi, distinti dai pass.

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
finestra pending non consumabile e rilascio del flag sticky; il flag
numerico sincrono riusa invece un buffer privato di 256 B, mantenendo
reset, copie/fence necessari e capacità addebitata fino al cleanup.
L'owner corrente misura 42.096 B (+8 B rispetto allo storico 42.088 B).
Conta capacità simultanee e copie, senza scaricare matrici intermedie. Il driver simulato non esegue
o convalida i kernel CUDA. L'embedding aggiunge copie D2D per batch di
1, 4 e 150 token, osservazione dell'ordine esatto e 17 rifiuti, inclusi
token invalidi prima della prima copia ed errori dopo copie parziali.
Il link dell'owner ABI 4 richiede anche
`cuda/c71_dense_i16.cu`; Rust rifiuta librerie della precedente ABI.
Con un toolkit dotato di runtime statico usare `--cudart static` per la libreria;
non dedurre un errore dei kernel dall'assenza di `libcudart.so`.
I filtri ordinari `c71_b12_windowed_native_*` compilano una libreria host
temporanea del medesimo owner, con simboli CUDA fittizi e algebra di
riferimento, e la caricano nel prover Rust. Non caricano la libreria CUDA
reale; l'eccezione è il test ignored
`c71_b12_windowed_native_hardware_parity_explicit` del runbook H100.
Byte D10 usa finestre da 512 B, signed D12 da 4.096 B; l'arena
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
c71_seed6_native_full_o0_proof_promotes_same_receipt_after_role_journals
```

Per il range nativo riusare i filtri separati già elencati sopra;
il prefisso aggregato include molte fixture e non è un controllo unico
da 60 s.

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

Il [checkpoint capacità](../c7.1-history/crypto-capacity-close-2026-10-09.md) registra build O0/128 unit in
56,98 s, un job e picco RSS aggregato 2.560.106.496 B, senza AS per la
compilazione. I filtri nuovi, sempre separati AS 2 GiB/60 s, sono
`c71_canonical_public_metadata_`,
`c71_canonical_forms_constructor_capacity_public_upper_bounds`,
`c71_wire_typed_heap_counts_option_vectors_and_moving_growth`,
`c71_b12_linear_exact_record_capacity_preserves_bytes_and_transcript`,
`c71_b12_linear_preflight_caps_and_compaction_preserve_originals` e
`c71_canonical_original_batch_take_preserves_order_mac_and_rejects_mismatch`.
La parità lineare nativa completa passa in 43,71 s dopo avere aggiornato
solo l'arena della fixture a 2 MiB per i fattori residenti W. Fallimento
precedente e correzione del record bind (identity u32, quattro byte)
sono conservati. Il filtro
`c71_b12_gemma_kv_original_macs_split_across_three_ranged_roots_with_fresh_rows`
ha raggiunto 60 s: non ripeterlo sulla VM con un limite più alto.
Il ledger `--backend s1-prepared` richiede anche i marker tipati
CAPACITY, TELEMETRY, CLASS8_FORMS e CANONICAL_WIRE_HEAP, oltre alle
ricevute di geometria/owner riusate: input e hash sono nel record.
