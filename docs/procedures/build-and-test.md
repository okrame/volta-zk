# Build, test and generated artifacts

Read [current status](../c7.1/status.md) first. This procedure explains
how to run authorized work; it does not authorize a heavy build or E2E.

## Choose the check

Start with the narrowest relevant check. For C7.1 arithmetic/accounting:

```bash
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_c7_1_gemma_plan.py
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_c7_1_baseline_budget.py
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_c71_bootstrap.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/c7_1_gemma_plan.py
```

Python scripts use the repository `.venv`; `pytest` is the global uv tool.
Use the script/report named by the active design. Historical budget scripts
are reference diagnostics when their specific assumptions are needed.
Documentation changes need link, consistency and diff checks, not Rust/Lean
builds. Existing passing checks need repeating only after relevant changes.

For the B12 mathematical fixed-run composition, run the existing Python
`B12` algebra/accounting filter, bootstrap checks and baseline-budget checks.
The added finite checks cover a source-mask translation across all of a
root's exposures, same-source history including terminal absorption, and
the exact complete bounds with the additional caller resource envelope.
They do not execute the full native verifier or Gemma. Mathematical/doc
closure alone requires no Rust or Lean build; native refinement is separate.

Per il consumer BMMA EXP30 eseguire `tests/test_c71_exp30_bmma.py`:
sono oracoli CPU e controllo arena, senza prove canoniche né GPU. Il file
`cuda/c71_exp30_bmma.cu` compila come C++ per il controllo host, oppure con
`nvcc -O3 -std=c++17 -arch=sm_90 -Xptxas=-v -c` per i soli kernel. Conservare
SASS e ptxas; i siti BMMA statici di un ciclo srotolato non sono il conteggio
dinamico per tile. Il programma non contiene un percorso di lancio GPU.

## Rust and resource limits

Per il raccordo streaming critico, dopo la build PCS mirata, eseguire
separatamente `sourcewise_range_matches_dense_original_wire_and_mac`,
`c71_b12_sourcewise_linear_matches_dense_wire_fs_point_and_original_mac`,
`c71_b12_o0_reader_discovers_token_and_matches_numeric_source` e
`c71_b12_native_streaming_lookup_gkr_whir_positive_original_macs`, più la
regressione `c71_b12_native_composed`. Restano 60 s/2 GiB, un worker Rayon
e `--test-threads=1` per filtro. Con `C71_INTEGRATED_TRACE=1 --nocapture`
il positivo emette i contatori esistenti di GKR/lookup e i confini disgiunti
del getter; `c71_response_trace.reduced_joint_trace` controlla il ledger.
Non sono conteggi canonici completi, HBM o tempo H100. Il nuovo reader
è O=0: il test storico a tre tentativi continua a coprire il percorso denso.
Per il CUDA usare il controllo host preesistente, che ora verifica anche
main-cell e fold/coeff MSB fusi, e compilazione statica `sm_90`; nessuna
esecuzione GPU è autorizzata da questa procedura.

Per i pesi EXP30 posticipati aggiungere il filtro nativo
`c71_b12_pattern_prefix_four_rounds_original_wire_and_mac` e
`c71_b12_softmax_original_scores`; il primo usa wiring piccolo a 32 celle e confronta sia tile da cinque
bit sia momenti a un bit, con marker `C71_PATTERN_PARITY`.
Per i riporti e la cache originali aggiungere
`c71_pattern_wide_accumulator_matches_field_at_carry_boundaries` e
`c71_exp30_ratio_cache_matches_original_bytes_and_causal_padding`.
Per il DAG di replay aggiungere
`c71_pattern_replay_dag_matches_every_original_exp30_level`: usa solo
un gruppo packed per live mask e livello, senza inferenza canonica.
Il marker `C71_EXP30_REPLAY_DAG` alimenta `replay_dag_screen`, che verifica
i conteggi fissati usati dal ledger. Con
`C71_EXP30_SHARED_FIXTURE=/tmp/c71-exp30-shared-fixture.bin` lo stesso filtro
verifica la schedule parallela e genera un fixture pubblico di circa 45 MiB.
Passarlo come unico argomento al binario host di `cuda/c71_exp30_bmma.cu`
per confrontare tutti i livelli e controllare assenza di race fra slot
dello stesso stage. Il fixture si rigenera dalla SHA del codice; niente GPU.
Il trace integrato distingue `pattern_prefix` dai round scalari rimanenti.
I conteggi e la liveness sono controllati da
`tests/test_c71_exp30_alternatives.py` e dal filtro
`native_offsets_margin_and_fenced_release` di `tests/test_c71_arena_plan.py`.
Restano test ridotti con i limiti sopra; nessuna misura CUDA è implicita.


Per la riserva Seed6 eseguire separatamente `c71_seed6_tail_reservation`,
`c71_seed6_real_prefix_guard_and_exact_equality_tail` e `c71_seed6_equality`
nel binario PCG con feature `c71-b11`, dopo la build mirata. Il secondo
filtro usa due seed reali da 12 righe su socketpair Unix; il terzo comprende
il fixture reale da tre righe. Restano 60 s/2 GiB e un worker per invocazione,
nessun bootstrap canonico, GPU o rete esterna.

Per il GKR a getter e l'endpoint byte a LUT, dopo la build mirata PCS sotto,
eseguire separatamente `fs_streamed_record`, `c71_b12_byte_functions`,
`c71_b12_single_cell_sourcewise`, `c71_b12_rms_joint_gkr`,
`c71_b12_ratio_joint_gkr`, `c71_b12_replay_crosses_u64`,
`compact_frames_match_original`, `c71_b12_gemma_rms_dispatch` e
`c71_b12_native_composed`. Restano 60 s/2 GiB, un thread e un worker Rayon
per invocazione; il caso u16/N=128 è il più costoso e non va ampliato.
`--nocapture` emette i contatori `C71_SOURCE_WORK` e `C71_BYTE_SOURCE_WORK`.
Per il lookup compatto aggiungere `source_lookup_matches_dense`,
`c71_b12_lookup`, `c71_b12_gemma_gelu_sources` e `c71_b12_gemma_output_head`;
`C71_LOOKUP_SOURCE_WORK` confronta cache/cut/Eq con il ledger Python.
Il census GKR aggiunge capacità native e distingue i payload canonici.
Dopo modifiche alle fold condivise mantenere anche
`incremental_prefix_weights`, `selected_layer_replay`,
`sourcewise_real_boolean_replay`, `maximum_checkpoint_and_source_tree` e
`c71_b12_softmax_original_scores`; compilare
separatamente `volta-field --lib --no-run` con gli stessi env/job e usare
il filtro `fp3_` per codec, prodotto e maschera Boolean.
La parità con la prova densa è controllo ridotto di transcript/MAC/PCS;
non esecuzione canonica né misura H100. Il ledger Python usa
`tests/test_c71_gkr_screen.py` e `tests/test_c71_arena_plan.py`.


Per il percorso composto ridotto, compilare solo `volta-pcs` con il target
canonico assoluto e `CARGO_INCREMENTAL=0` come sotto:

```bash
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_DEV_OPT_LEVEL=2 cargo test --offline --locked -j 1 -p volta-pcs --features c71-b12-pcs --lib c71_b12_native --no-run
```

Eseguire il binario test stampato da Cargo con un filtro alla volta:
`c71_b12_native_prepare`, `c71_b12_native_composed`,
`c71_b12_native_certificate`, `c71_b12_native_interrupted`,
`c71_b12_native_context`, `c71_b12_native_consistent_inference`,
`c71_b12_native_changed_predecessor`, `c71_b12_native_exhaustion`.
Ogni invocazione usa `--test-threads=1`, `RAYON_NUM_THREADS=1`,
`timeout 60s` e `ulimit -v 2097152`; nessun caso si esegue in parallelo.
Sono test composti con MAC ideali, non bootstrap AES delle 797.139 righe
base equivalenti. Non avviare quest'ultimo sulla VM. Per le tabelle usare
il filtro Python `native_small_profile`; dopo modifiche al codec PCS
conservare anche i test campo/FS e salted/codec preesistenti.
Vedi [perimetro ed evidenza](../c7.1/evidence.md#native-bounded-composition).

Il filtro `c71_b12_native_canonical` controlla il compilatore causale di
tutte le sorgenti pinned a O=0/150/300, senza witness o domini densi.
`c71_b12_native_pool_packing` controlla conversione Fp3 e identità del
registro; `c71_b12_native_pool_real_shortage` usa una sola capacità AES
da tre righe per verificare il rifiuto del wrapper prima di Prepare/decode.
Quest'ultimo richiede soltanto una socketpair Unix locale; mantenere gli
stessi limiti di 60 s/2 GiB e un worker Rayon. Non esegue il percorso
AES composto positivo da 797.139 righe base, tuttora escluso sulla VM.
Dopo modifiche al lifecycle compilare anche `volta-pcg --features c71-b11
--lib c71_b12 --no-run`, con gli stessi env e un job; eseguire i filtri
`c71_b12_fixed_run_stops`, `c71_b12_burns`, `c71_b12_fixed_run_real_capacity`
separatamente. I test di regressione precedenti conservano i propri limiti.

`c71_b12_native_dispatch` controlla il nuovo corpo del verifier canonico
nei tre contesti: riserva esatta, identità del profilo, forme pubbliche,
framing iniziale e rifiuto di una prova P0 con zero coorti. Usa chiavi
ideali e tabelle parzialmente placeholder, nessun witness D34/D35 o
bootstrap. Eseguirlo separatamente entro 60 s/2 GiB con un worker Rayon.
Il successo del test è il rifiuto al confine previsto; non è accettazione
di un certificato canonico completo. Dopo modifiche ai helper condivisi,
conservare `c71_b12_native_composed` e `c71_b12_native_certificate`.

`c71_b12_native_registry` controlla il wrapper canonico: identità dei corpi
delle tabelle, header dal registro, mutazioni del contesto e arresto reale
per riserva insufficiente. Compila solo descrittori pubblici e usa una
socketpair con capacità AES di tre righe, con gli stessi limiti 60 s/2 GiB.
Non esegue un certificato positivo né il bootstrap canonico completo.

Per la preparazione RMS condivisa eseguire separatamente
`c71_b12_native_norm_rows`, `c71_b12_rms_public_circuit`,
`c71_b12_ratio_circuit`, `c71_b12_native_prepare` e
`c71_b12_native_composed`, sempre entro 60 s/2 GiB e un worker Rayon.
Il primo valuta righe sintetiche per le 421 norme canoniche, senza W/A
completi; i due circuiti controllano semantica e geometria preesistenti.

Per la preparazione RNE condivisa eseguire separatamente
`c71_b12_native_rne_rows`, `c71_b12_rne_recipes`, `c71_b12_ratio_circuit`,
`c71_b12_native_prepare` e `c71_b12_native_composed`, con gli stessi limiti.
Il primo controlla righe sintetiche delle 892 coppie nei tre contesti;
il secondo le 64 classi di shift contro i polinomi byte del verifier.

`c71_b12_native_wire` controlla il limite inferiore RNE sul codec canonico
(solo metadati, `--nocapture` stampa il censimento) e il limite del writer
comprensivo del record finale. Il test di trasporto usa un buffer di
16 MiB, senza witness; mantenere 60 s/2 GiB e un worker Rayon.
`c71_b12_rne_ties_overflow` confronta il conteggio wire con una prova
componente realmente serializzata. Conservare `native_composed` e
`native_certificate` dopo modifiche al writer.

Per l'esperimento di P/S RNE condivisi eseguire separatamente
`c71_b12_rne_joint_bytes_valid_proofs_and_original_pcs` e
`c71_b12_rne_joint_bytes_canonical_geometry`, con `--nocapture` per i byte.
Stessa build mirata, un worker Rayon, test seriali entro 60 s/2 GiB.
Il primo usa due RNE e una PCS reale nel modello MAC ideale; il secondo
solo descrittori e forme wire sintetiche D34/D33. Il prover sperimentale
è test-only e rifiuta viste dense sopra D9. Dopo la separazione della
riduzione RNE conservare `c71_b12_rne_recipes`, `c71_b12_rne_ties_overflow`,
`c71_b12_byte_functions`, `c71_b12_native_prepare`, `c71_b12_native_composed`,
`c71_b12_native_certificate` e `c71_b12_native_canonical_wire_body`.
Non viene autorizzata la materializzazione dei gruppi canonici.

Per la preparazione affine condivisa usare `c71_b12_native_affine_rows`,
`c71_b12_gemma_affine`, `c71_b12_native_prepare`, `c71_b12_native_composed`
e `c71_b12_native_certificate`, separatamente entro 60 s/2 GiB e un worker.
Il primo copre le 181 relazioni canoniche con righe sintetiche; non è
un'esecuzione del grafo completo.

Per lo screen PCS/stato usare `scripts/c71_pcs_state_screen.py` e
`tests/test_c71_pcs_state_screen.py`, oltre ai filtri Python
`canonical_PCS_wire or native_wire_body or complete_fixed_run`.
Con la stessa build mirata, eseguire separatamente
`c71_pcs_tuning_valid_original_mac_and_codec`,
`c71_pcs_tuning_canonical_geometry`,
`c71_rne_unpadded_groups_cover_without_extra_cells` e
`c71_b12_rne_joint_bytes_canonical_geometry`: un worker Rayon,
`--test-threads=1 --nocapture`, 60 s/2 GiB per invocazione.
Il positivo PCS è D12/D13; i conteggi D34/D35/D36 sono codec sintetici.
La geometria include W installato a una esposizione e stato unico D36
a due; il dispatch canonico non ammette per questo il nuovo dominio.
Conservare
il positivo RNE condiviso, il codec PCS B12 e la composizione ridotta dopo
cambiamenti ai helper. Nessuno di questi controlli esegue lo stato mobile
canonico, misura il lavoro completo o amplia l'autorizzazione hardware.

Per il confronto completo ridotto con stato unico eseguire separatamente
`c71_joint_inference_same_model` e `c71_joint_inference_changed_last`,
con gli stessi limiti 60 s/2 GiB e un worker. Il primo confronta tre
certificati completi B12/candidata e include rifiuti di troncamento e
cardinalità RNE; il secondo prepara una continuazione su ultimo KV alterato.
Sono MAC ideali e domini D12/D13, senza credito canonico o di lavoro totale.
Dopo cambi al corpo condiviso conservare gli otto filtri nativi sopra,
`c71_b12_rne_joint_bytes_valid` e `c71_rne_unpadded_groups_cover`.

`c71_pcs_retained_commit_data_preserves_wire_and_removes_rebuild` confronta
commit ricostruito e dati conservati con lo stesso tape: PCS/MAC, byte/FS,
indirizzi dei buffer e trace DFT. Usa gli stessi limiti seriali 60 s/2 GiB.
Il caso D10 senza switch conserva il rifiuto del codec C71 dell'oracolo
finale base e confronta serde/FS; solo D12 concede byte nativi identici.
Dopo modifiche al motore condiviso conservare PCS valida, salted/codec,
campo/FS, `c71_b12_native_composed` e `c71_b12_native_certificate`.

Per la transizione W/A/KV sperimentale eseguire separatamente i filtri
`c71_joint_state_three_transitions`, `c71_joint_state_changed_installed_w`
e `c71_joint_state_changed_last_accepted_kv`, con gli stessi limiti seriali
60 s/2 GiB e un worker Rayon. Usano W/D12 e S/D13, MAC ideali, due PCS,
range W/A e framing; non eseguono inferenza/RNE, AES o domini canonici.
Dopo modifiche al costruttore con conservazione e a `prove_pcs`, mantenere
il confronto byte/FS dei dati conservati, campo/FS, salted/codec e i due
test composti ordinari, oltre al positivo dei parametri PCS sperimentali.

Il filtro Python `canonical_PCS_wire or native_wire_body or complete_fixed_run`
controlla il corpo canonico contro i censimenti field già presenti e
il conteggio PCS di maschere, sali, frontiere e aperture storiche.
Non compila Rust né misura prove valide; preservare le etichette di
lower, upper e fixture sintetica quando si riusano questi numeri.

Il filtro Rust `c71_b12_canonical_pcs_codec` controlla le forme del codec
D34/D35 con byte e frontiere sintetici, senza witness, Merkle tree o pool.
Usare la stessa build mirata e il limite seriale di 60 s/2 GiB. Il roundtrip
strutturale non è verifica crittografica positiva; il test non esegue Gemma.

`c71_b12_native_canonical_wire_body` fa roundtrip dei tipi `Wire` di tutte
le famiglie non-PCS con descrittori canonici nei tre contesti e fixture
nulle, entro gli stessi 60 s/2 GiB e un worker. I due GKR usano l'envelope
di forma, non circuiti calibrati. Il test assembla anche il framing completo
con PCS massime, senza verifier crittografico. Dopo modifiche ai cap eseguire
separatamente `c71_b12_native_wire_limit`, `c71_b12_canonical_pcs_codec`,
`c71_b12_native_composed`, `c71_b12_native_certificate`, dispatch/registro
e le regressioni campo/FS e salted PCS indicate sotto. I cap canonici
96/16 MiB non autorizzano witness o bootstrap dei domini D34/D35.

The [current evidence ledger](../c7.1/evidence.md) distinguishes the final
profile from the individual component fixtures catalogued below. Intermediate
D31/D33 source counts and partial target/cube totals describe those fixtures,
not the final D34 auxiliary source. Mathematical composition is complete;
references below to unexecuted composition concern the native full-model path.
No native tests were rerun for the documentation reorganization.

Rust is installed through rustup. All Cargo commands, including standalone
third-party manifests, share the absolute repository `rust/target`:

```bash
source "$HOME/.cargo/env"
export CARGO_TARGET_DIR="$(git rev-parse --show-toplevel)/rust/target"
export CARGO_INCREMENTAL=0
cd rust
cargo test --workspace
```

This is the broad workspace command, not the default check for every task.
For the authorized B9 component, run from `rust` with the same absolute
target and `CARGO_INCREMENTAL=0`:

```bash
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_DEV_OPT_LEVEL=2 cargo test --offline --locked -j 2 -p volta-pcg --features c71-bootstrap c71_b9 -- --test-threads=1
```

From the repository root, `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python
scripts/run_c71_bootstrap.py --n 3` runs one OS-random two-role component
case; `--n 32` is the other registered size and `--fault` selects a bounded
adversarial case. It reuses the existing 60 s / 2 GiB / two-thread launcher,
uses only local Unix socketpairs and preserves failures. The script builds
only the `volta-pcg` example at opt-level 2, with no separate Cargo target.
This is not the stopped B7 matrix runner or a full Gemma E2E. The source
tree must be clean for a run of record; a detached temporary worktree can
preserve unrelated edits while sharing the canonical target.

For the owner-authorized B11 intermediate component, the same runner accepts
`--suite b11 --n 180` or `--n 207`, and `--suite b11 --n 3 --fault ...` for
the ten byte faults. It builds only the example with `c71-b11`, including
the existing MAC consumer diagnostic. Limits remain 60 s / 2 GiB / two
threads. Run the narrow native tests using the command above with
`--features c71-b11 c71_b`; this also retains the B7 negative and B9 checks.
The Python bootstrap/budget checks cover the conditional lifetime arithmetic.
These are component checks, with no durable-pool or PCS/Gemma admission.

For the owner-authorized B12 finite-pool component, the same narrow Cargo
command with `--features c71-b11 c71_b12 -- --test-threads=1` checks the
durable journal, completion-seal framing, subprocess crash/reopen and real
two-role MAC transfers. The new fixed-run profile is exercised at 258 base
rows with small IO operations; four AES path vectors cover larger domains
without allocating their capacities. Failure checks reject continuation,
downgrade and reopen. Do not run the 108,201-row or maximum-capacity cases
locally: their diagnostic entries are arithmetic only.
The real role checks need only a local Unix socketpair, as B9/B11 did;
if the sandbox denies it, permit that local test without external access.
No full workspace, matrix/Gemma runner or paid hardware is needed. These
are component tests, not run-of-record benchmarks or complete security evidence.

For the B12 salted PCS consumer, build only `volta-pcs` with the same Cargo
target and profile, `--features c71-b12-pcs --lib`, and run the narrow filters
below with one test thread. After compilation, bound each test invocation
to 60 s and 2 GiB, with `RAYON_NUM_THREADS=1`. Its component tests cover
FS coin-block replay, unique-radius geometry (D35 configuration only), private
coin streams, salted Merkle/codec and three attempts of a 48×48 synthetic matrix using the real
180-row B11 roles and durable journal. The linear-form checks cover aligned
cubes and a 207-row real-B11 capacity: four original target MACs reach one
root/PCS, then a fresh false norm target is rejected and the run ends.
The same check also exercises the new single-setup AES profile, including
continuation after acceptance and termination after rejection.
The ideal-MAC simulator check uses only DV keys, public IO and a dummy
zero-weight PCS; it needs no socket or bootstrap and verifies the complete
certificate. Its acceptance check complements the mathematical ZK argument.
The range checks cover the full symmetric i16 table with ideal MACs, native
QuickSilver signs and a real fixed pool of 1,746 base rows. The latter
accepts [-3,3], rejects a false [-1,1] claim under the same root and ends
the run. These are small D10 cases, not a full Gemma range execution.
The separate `c71_b12_flat_sources` filter checks the same source/range/PCS
at D11 with 1,031 live signed/byte values, original target faults and
nonzero padding. It uses 344/593 ideal Fp3 rows. D34/D35 checks only
construct public profiles and framing; do not run full source allocations.
After shared source changes, rerun the existing range, linear, P0/Gemma
and matrix consumer filters in separate bounded invocations.
Run the `c71_b12_range` and `c71_b12_product_batch` filters separately
from the earlier PCS checks to keep each invocation below 60 seconds.
The `c71_b12_p0` filter executes a small raw matrix/norm/lookup caller
with 357 ideal Fp3 correlations, one ranged W PCS and a separate C/X PCS.
It checks committed false cuts and detached input MACs; no socket is needed.
The `c71_b12_gemma` checks cover native metadata/DAG layout and
physical/virtual addresses, including ragged tensor MLEs. The caller check
executes all 773 compact reductions with zero vectors and compiles the
original auxiliary forms; its placeholder roots grant no PCS acceptance.
A tiny actual raw graph uses 365 ideal Fp3 rows, a ranged W PCS and one
canonical auxiliary PCS, rejecting wrong head selection and proof assignment.
These checks read no full weight bodies and perform no Gemma inference
or D35/D31 PCS allocation; no socket is needed.
Run the two `c71_b12_softmax` checks separately. The selected EXP30 path
uses 8,096 ideal Fp3 rows with byte range and one shared A PCS; six faults
cover maximum, lookup, denominator, ratio, detached score and forbidden Pi.
Its kernel uses 2,360 FS draws; total PCS draws vary with public sampler
retries. Metadata cover all three canonical KV contexts and original source
forms; no full Gemma body is allocated. The wide lookup preserves legacy
i16 framing; rerun `c71_b12_lookup` and affected Gemma callers after edits.
The separate `c71_b12_profile` check derives all canonical numeric recipes
from one synthetic scale map across O=0/150/300. It checks missing/extra
scales, tied W exponents, Pi=-14 and coupled score/EXP30 changes; no
Gemma witness, calibrated table generation or physical execution is involved.
It also checks unique producer coverage of all 1,435 semantic i16 sources,
preservation of the 410 original RNE MACs/points and the disjoint 482 probes.
The byte bridge checks biased i48/i32/i16 source forms, signed extrema,
physical byte addresses and incorrect affine shifts with 551 ideal Fp3
rows and one ranged byte PCS. The `c71_b12_range_bytes` filter separately
covers every unsigned byte and rejects −1/256 in 542 ideal rows. The
full D33 byte-source geometry remains arithmetic only; no allocation/run.
The `c71_b12_byte_functions` check uses 809 ideal Fp3 rows for public
byte functions, range and one shared PCS. It rejects an incorrect function
at GKR and a consistent function of altered bytes at the original PCS.
After changes to the shared fraction-tree kernel, also rerun the existing
range byte/i16, product and P0/Gemma checks in separate bounded invocations.
The `c71_b12_rne` filter checks all 64 RNE recipes, degree seven and an
executed 951-row ideal case with one ranged auxiliary PCS. It rejects
wrong output, ±32768 overflow and a different raw source with the same
rounded output. This is a single public shift with c<=7 cell bits, not
the full calibrated Gemma RNE caller or a new hardware measurement.
The new `c71_b12_gemma_p0_rne` case uses 1,355 ideal rows and both
ranged PCS. It passes the norm P0's original X MAC to RNE of the preceding
matrix cut, with canonical ragged byte forms; wrong quantization or a raw
getter changed after commitment rejects. The norm remains a raw weighted
product, with no RMS denominator or full Gemma credit.
The full layout check also compiles all 240 direct P0-to-RNE requests
(q/k/o/down projections), checks their original MAC/point identities and
3,840 byte cubes. Only the tiny graph executes RNE; the full-domain
composition and correlation upper remain analytic.
The `c71_b12_rms` filter checks the public exact integer compiler against
five existing Boolean-reference profiles, plus joint authenticated GKR on
weighted/unweighted cells and dummy padding. The 7,299-row ideal case
reduces its ORIGINAL input-bit sum through byte P/S into one ranged PCS.
It rejects wrong Y and changed S preserving the same Y. There is no bit
reauthentication or trace PCS. This proves the RMS predicate on committed
P/S/Y bytes, before the canonical P0/statistic/output source routes;
full calibrated Gemma profiles and native complete composition remain open.
Run `c71_b12_replay` separately for the 128-cell joint GKR check. Its
small parity circuits use 421 public profile indices and one ranged D12
A PCS, with faults past cell 63 and a 256→0 index substitution. It uses
1,278 ideal Fp3 rows and 173 kernel draws; no canonical dense domain is
allocated. The shared GKR/P-S changes also require the existing
`c71_b12_rms`, `c71_b12_ratio`, `c71_b12_byte_functions` and
`c71_b12_softmax` filters in separate bounded invocations.
The two `c71_b12_ratio` checks reuse the RMS builder for exact signed
RNE(2^m*P/Z), m=0..14, including ties, overflow and positive-denominator
guards. The 7,164-row ideal case closes the original numerator,
denominator and output through byte P/S, range and one PCS; a changed
numerator preserving Y still rejects. After this shared builder refactor,
also run `c71_b12_rms` separately to retain its exact circuit counts.
The ratio component does not by itself prove the selected EXP30 producer
or execute full-domain normalization.
The `c71_b12_rms_statistic` case uses 7,761 ideal rows for weighted P0,
S=sum X², joint exact RMS and both ranged PCS. One S word per row is
broadcast through the same byte view. A changed statistic preserving Y
fails the square relation; a changed weight getter with consistent P/Y
fails the original W PCS. Full 421-cohort Gemma execution remains open.
The `c71_b12_gemma_rms` check compiles all 421 canonical RMS source
routes, including ten global pre-norm K/V aliases. A literal small byte
view checks head reshape, S broadcast, reused Y and the final selected
rows. It also counts the D33 extension and its 48,026-cube known batch including 50 local V RNE;
no full source body or RMS trace is allocated. The current linear bridge
permits 524,288 public cubes; the public matrix
runner remains D14, while internal Flat sources support D10–D35. These
geometry checks do not execute a full source body. After the shared byte
form refactor, rerun the full `c71_b12_gemma` filter for the existing
P0/byte/RNE cases; actual full-domain dispatch remains open.
The `c71_b12_gemma_rms_dispatch` case executes a canonical small graph
with 10,003 ideal Fp3 rows: P0, all its RMS/statistics, direct q/k RNE,
local V RNE and both ranged PCS. Original embedding-input MACs also
open the same W. V altered with consistent S/Y fails RNE; norm weights
altered with consistent P/Y fail the installed W PCS. The executed dispatcher check remains small; its public preflight now
covers D29/421 profiles. This is no calibrated full-model run.
Run `c71_b12_preflight` separately for the canonical complete reservation.
It uses synthetic public scales and an exact e_score=128 EXP30 table in
all three KV contexts, without expanded cell/query arrays. Zero-capacity
prover calls must reject before the witness getter or any FS change. It
uses placeholder roots and gives no proof, calibration or hardware credit.
The complete count covers all operators and W/A openings: 11,187,057 base
rows for this profile, below the conservative 11,466,948-row bound.
GELU/softcap/RoPE tables are shape-only placeholders, not certified contents.
The P0 check now accepts public geometries through D32 and rejects D33;
its actual matrix/norm/lookup proof remains the existing small case.
The `c71_b12_lookup` filter checks two restricted GELU tables against one
fixed byte source with 600 ideal Fp3 rows, including range and shared PCS.
It rejects wrong output, overflow, and an input/histogram pair changed
coherently after commitment. The v2 check interleaves query/table blocks
and rejects incomplete/duplicate table coverage. The unchanged shared
fraction-tree kernel needs no broad rerun.
The `c71_b12_gemma_gelu_sources` case compares a small extended byte view
and original X/Y/M forms, then counts every pinned GELU route and all
1,680 compact blocks without full bodies. RMS/P0 source IDs are preserved.
It also dispatches the full certified integer (0,0) GELU table and one gate
RNE using 1,158 ideal Fp3 rows. This source-view check uses placeholder roots
and does not execute a D19 or full D33 source PCS. Python compares all
65,535 entries with the exact existing public-table generator.
The `c71_b12_gemma_table_rne` case extends the ragged P0/RNE graph to
an original whole-table X probe with 1,356 ideal Fp3 rows and both ranged
PCS. It rejects wrong output, a changed raw that preserves rounding,
invalid source codecs and insufficient capacity before witness reads/use.
After changes to the shared byte extension, rerun the `c71_b12_gemma`
filter for the existing P0/byte/RNE/RMS cases, within the same small limits.
The `c71_b12_gemma_gate_up` filter executes product and both RNE with
1,372 ideal Fp3 rows and one ranged A PCS. It rejects a wrong raw product
and swapped G/U with a consistently changed up raw. Its separate canonical
view check dispatches a 21-row product and compares forms with literal
bytes, with placeholder roots and no PCS acceptance. Full pinned metadata
checks the 60 original down-P0 demands and D34 counts without source bodies.
Source RNE views accept only biased-i48; matrix view transcripts are preserved.
The `c71_b12_rope` filter checks the joint Q30 public adjoint on aligned
dyadic blocks, full half-head pairing, inactive pairs and absolute positions.
Its 559 ideal Fp3 rows include one ranged A PCS; wrong raw fails the linear
GKR and a coherently changed Y/raw pair fails that original PCS. It also
rejects misaligned blocks and exhausted capacity before witness reads.
Python checks the three active j=0 coefficient pairs against the existing
exact Q30 recipe. The `c71_b12_gemma_rope_sources` case compiles all 120
canonical original RMS/raw/output routes and checks 480 blocks, both raw/Y
forms and 120 RNE pairs, without the full source body. Its synthetic table
bodies check shape/context only; they are not certified Q30 or execution
evidence. The current check accepts the D27 public reservation without FS draws;
the RoPE public geometry guard is now D29. No full-domain body is executed.
After generic non-matrix raw RNE changes, rerun the entire small
`c71_b12_gemma` filter to retain P0/GELU/gate-up behavior.
The two `c71_b12_attention` cases use 571/572 ideal Fp3 rows and an actual
ranged A PCS for QK/PV, including the original contracted-M-to-Pi link.
They reject wrong raw/GQA/query padding, detached M and source operands
changed consistently with the raw. The current public QK geometry guard is D31;
no full attention, softmax, accepted-KV history or Gemma execution is implied.
After changes to shared P0, rerun `c71_b12_p0`, `c71_b12_gemma` and
`c71_b12_rms_statistic` in separate bounded invocations.
The `c71_b12_gemma_attention` metadata check compiles the fresh O=0 routes
from original RoPE/RMS/P0, all 120 RNE obligations and 4,189 known A targets.
It checks D34/65,067 cubes without source bodies or full-domain attention.
The current linear target/cube guards are 8,192/524,288; public geometry
admission does not authorize dense allocation.
After the source extension, rerun all small `c71_b12_gemma` checks; the
placeholder-root metadata case grants no source PCS acceptance.
The `c71_b12_gemma_affine` case uses 991 ideal Fp3 rows for a public
zero source form, ragged RNE, byte range and the same PCS. It rejects
wrong raw with the same rounding, a changed input/raw pair detached from
A and wrong output. The form itself uses no private correlation.
The `c71_b12_gemma_residual` metadata case checks all 181 canonical
residual/scale routes, the exact verified public BF16 coefficients and
181 RNE pairs, with a synthetic exponent map and no full witness.
Its 79,539-cube partial batch fits the current 524,288-cube guard.
This remains a metadata check; the public matrix runner stays D14. Rerun
the full small `c71_b12_gemma` filter after
source extension; full-domain RNE and calibrated profiles remain separate.
The `c71_b12_gemma_kv` case uses three component attempts with 544/577/610
ideal Fp3 rows, including incoming original K/V MACs, new-source range and
all source PCS. Prior A0/A1 receive fresh current-attempt MACs and PCS;
wrong incoming K or an altered old getter reject without receipt promotion.
It also checks canonical 150-row segment forms at offsets 0/150/300 using
metadata only. These receipts certify component byte/PCS checks, not full
Gemma execution. The `c71_b12_gemma_attention_continuations` metadata case
checks O=0/150/300, absolute RoPE windows, all original K/V routes and
the three A layouts. It rejects stale positions, a substituted current
root and a fourth segment, without allocating full sources. The Python
B12 checks recompose six A openings, 39 streams and 526 trees; full
accepted Gemma state and calibrated execution remain open.
The `c71_b12_gemma_argmax` case proves three public decisions with
unsigned byte slacks and a single ranged PCS (542 ideal Fp3 rows),
rejecting wrong decisions, tie order and slack. Its full-size metadata
check compiles 50 decisions into 56 cubes without allocating A.
Run the Python filter `B12 or gelu or softcap` after changes to the
shared public exponential enclosure: it preserves GELU and checks
softcap's strict tails, overflow and fail-closed public preparation.
The `c71_b12_gemma_output` case now connects raw head RNE, a certified
small softcap table, public argmax, range and the same PCS using 1,112
ideal Fp3 rows. Wrong raw, softcap and tie decision reject at their
respective checks. Its metadata portion compiles all three canonical
output layouts and original P0 raw IDs; no full D24 lookup/RNE runs.
The same case now checks a designated-verifier simulator with zero dummy
raw/X/Y/slack and arbitrary public tokens. It retains the verifier's
public target key using Delta; this is no malicious-prover capability.
Acceptance supports the documented component simulation argument, not
full-Gemma ZK by itself.
After extending output sources, rerun `c71_b12_gemma` within the same
60 s/2 GiB limits. Calibrated full output and native complete Gemma
simulation remain open.
The Python `softmax_exp30` filter checks the owner-selected numerical recipe,
including its certified difference from RNE of the real softmax. Its
passing test does not by itself change the B12 security total.
The `c71_b12_gemma_causal_mask` case uses 542 ideal Fp3 rows and a
shared ranged PCS to reject nonzero Pi at a future key or padded query.
Nonzero allowed values pass: the mask acts at Boolean source vertices,
not as a product of two independently extended tables. The metadata
check covers every query/key of O=0/150/300 and all 60 canonical Pi IDs,
with at most 111,306 cubes in the composed A batch. Run `c71_b12_gemma`
after changing these routes, and the Python `B12` filter for the added
FS/cube/resource accounting. No full body or softmax producer is executed.
After byte-function changes, rerun `c71_b12_byte_functions` and
`c71_b12_rne` separately; ordinary lane-mode transcripts are preserved.
This internal bridge uses in-memory proof transport; it is not a Gemma runner
or standalone wire codec. These checks need only local Unix socketpairs.
The existing field/FS checks use `c71_matrix::tests::` with that feature.
The old B7 matrix runner rejects this feature before setup. This is an
opt-in component check, not a complete admitted PCS or Gemma execution.

Before a broad local build, check guest space and confirm at least 60 GiB free
on the host; guest `df` alone does not establish host capacity. Run the full
workspace before a protocol milestone checkpoint when authorized resources
permit; otherwise state the validation gap. Heavy benchmarks and full-model
E2E belong on authorized hardware, not the local VM. The owner's 2026-09-08
exception allows a small synthetic CPU E2E on this VM, within the
[bounded experiment contract](../c7.1-gemma31b-design.md#esperimento-ridotto-contratto-e-ambito-del-runner).
It does not authorize a broad build, GPU/provider access or paid resources.

Do not create per-crate, top-level or experimental Cargo targets. Remove the
canonical target and ignored nested Cargo targets after a milestone checkpoint
and before leaving the session; keeping a build cache requires owner approval.
`rust/.cargo/config.toml` pins `target-cpu=native`: timing is machine-specific.
Re-measure the registered paired baseline before quoting rates on another CPU.
Reports use `cargo run --release -p volta-bench --bin <report>` with the active
design's report and workload.

## Getter e hash C7.1 ridotti

Per il checkpoint 512 replay compilare soltanto `volta-pcs` con le opzioni
sopra, dalla directory `rust` (così si applica `.cargo/config.toml`). Usare
il target canonico, un job e nessuna build workspace. Eseguire separatamente
`c71_b12_native_ordered` e `c71_b12_streaming` con un worker Rayon,
`--test-threads=1 --nocapture`, `timeout 60s` e `ulimit -v 2097152`.
Il primo confronta i byte originali su O=0/2/4; il secondo sali, seek,
rigetti, overwrite in-place e root strided contro la MMCS nativa. Sono
input ridotti CPU, senza snapshot/PCS canonici o esecuzione GPU.

Dopo modifiche all'evaluatore condiviso conservare `c71_b12_native_prepare`
e `c71_b12_native_composed`; dopo modifiche a hash/coin conservare
`c71_b12_private_coins`, `c71_b12_salted_merkle` e
`c71_b12_canonical_pcs_codec`. Ogni filtro mantiene gli stessi limiti.
Il ledger si controlla con `tests/test_c71_whir_trace.py`,
`tests/test_c71_ordered_getter.py` e `tests/test_c71_arena_plan.py`.
Il report nuovo può riusare i trace pubblici del record congelato indicando
file, SHA e digest; non può riattribuire al checkpoint nuovo un vecchio
run o una misura hardware. La variante 1.024 non si riesegue.

## Lean and generated assets

Formal M1–M11 milestones are closed and frozen. Open Lean only when the protocol
statement requires it; if authorized, use `export PATH="$HOME/.elan/bin:$PATH"`,
then `cd lean && lake build`. Remove `lean/.lake` after the checkpoint unless
explicitly retained.

Weights and generated golden artifacts under `benchmarks/weights/` are produced
only by the registered export/dump scripts and are not newly committed as model
assets. Preserve existing tracked fixtures and evidence. The frozen GPT-2
[quantization spec](../quantization-spec.md), `scripts/gpt2_fixed.py` and Rust
forward must remain bit-identical when that baseline is touched. C7.1 requires
its own [Gemma semantic/runtime correspondence](../c7.1/design.md#native-correspondence);
GPT-2 golden success does not validate Gemma.

Raw runs are new files under `benchmarks/results/<milestone>-<date>-<gitsha>.json`.
Keep every failure and all framing/resource costs. A run of record requires a
clean source tree and `git_dirty: false`; corrections go in a new linked record.

### Replay WHIR e codec cGGM ridotti

Il confronto sourcewise usa la build mirata `volta-pcs --features c71-b12-pcs
--lib --no-run`, con gli env e il target canonico già indicati. Eseguire
separatamente i filtri `c71_b12_sourcewise_adaptive`, `b12::replay`,
`b12::streaming`, `c71_b12_native_composed` e
`c71_b12_native_certificate`. Il test della catena stampa il codec canonico
e il censimento per fase dell'allocator CPU; il reset VmHWM riguarda solo
il processo corrente. Non sono workspace o service-rate GPU. Conservare
anche il filtro `c71_b12_canonical_pcs_codec` dopo modifiche al codec.

Per il codec EA-LPN usare la build mirata
`volta-pcg --features c71-b11 --lib --no-run` e il filtro
`c71_ea_lpn::tests`. Comprende vettori Rust/Python, esaurimento sampler,
identità dei ruoli a profondità 1–7. Non esegue OT o bootstrap AES completo.
Ogni invocazione resta seriale con `RAYON_NUM_THREADS=1`, `timeout 60s` e
`ulimit -v 2097152`; non avviare i due binari in parallelo.

Per il collegamento getter/PCS eseguire separatamente
`c71_b12_ordered_sourcewise_o0`, `c71_b12_ordered_sourcewise_o2` e
`c71_b12_ordered_sourcewise_o4`, con gli stessi limiti. Il riferimento
indipendente materializza solo il dominio piccolo; il callback del prover
conserva una finestra, cut e KV. Per Seed6 usare `c71_seed6::tests`, più
`c71_b9_` dopo modifiche al motore MR19 condiviso. Il test a 384 OT richiede
una socketpair Unix anonima fra due ruoli, senza connessioni esterne;
se il sandbox la blocca, usare l'eccezione locale circoscritta. Non esegue
il bootstrap canonico o la seconda installazione con ruoli opposti.

Il filtro `c71_row_work_counts` controlla il censimento dei passi ridotti;
conservare `c71_b12_native_prepare` e `c71_b12_native_composed` dopo modifiche
al valutatore condiviso. Il censimento distingue i helper ancora opachi e
non fornisce conteggi completi del modello canonico o del producer GKR.


### Coefficienti RMS sourcewise e censimento pubblico

Stessa build `volta-pcs --features c71-b12-pcs --lib`, un job e target
canonico assoluto. Eseguire separatamente entro 60 s/2 GiB, Rayon=1:
`compact_frames_match_original`, `sourcewise_cell_coefficients_match_dense`,
`sourcewise_real_boolean_replay`, `selected_layer_replay`,
`c71_b12_preflight_norm_and_exp30_counts`,
`c71_b12_softmax_canonical_sources_and_vertex_forms_cover_all_three_attempts`.
Gli ultimi due richiedono `--nocapture` per salvare i log del censimento.
Conservare `c71_b12_rms_public_circuit`, `c71_b12_ratio_circuit` e
`c71_b12_native_composed`; nessun witness canonico.

Il report `scripts/c71_gkr_screen.py --rms-log RMS_LOG --ratio-log RATIO_LOG
--sass SASS_FILE` confronta i supporti/circuiti pubblici e conta solo i
kernel standalone esplicitamente presenti nel dump SASS. Non usa tempi
GPU. Compilare il solo `cuda/c71_range_microbench.cu` per sm_90 con `-cubin`,
poi `cuobjdump -sass`, secondo il toolchain locale già registrato.
Non avviare `--gpu`. I test Python pertinenti sono
`tests/test_c71_gkr_screen.py`, `tests/test_c71_range_microbench.py` e
`tests/test_c71_arena_plan.py`, in seriale entro gli stessi limiti.
