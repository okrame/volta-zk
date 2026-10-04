# C7.1 — test su RunPod

[Design](design.md) · [Specifiche](specs.md) · [Sicurezza](security.md) ·
[Test locali](local-tests.md) · [Archivio](../c7.1-history/README.md)

## Stato e sequenza operativa

Il runner locale `experiment-cuda` collega inferenza/replay dei 13 producer,
owner comune, range residente, PCS/GKR CPU, verifica e promozione per
O=0/150/300. È pronto per il **primo esperimento autorizzato**, non già
validato sulla H100. Nessun certificato canonico, tempo completo o
rispetto dei target è acquisito. Il readiness audit storico
[NOT_READY](../../benchmarks/results/c71-h100-e2e-readiness-2026-10-03-fbd6141e7a1e.json)
resta immutabile, ma non descrive l'assenza attuale del codice del runner.

Questo documento non autorizza campagne. L'istruzione corrente del proprietario
fissa pod, fasi autorizzate, durata massima, responsabilità di spegnimento
e destinazione degli artefatti; può includere calibrazione e prova nella stessa campagna.
Il successo numerico non dimostra la prova né estende l'autorizzazione.
Su un pod già noleggiato si verificano termine e possibilità di spegnimento,
senza richiedere una nuova creazione o ripetere un'autorizzazione valida.

**Controllo temporale.** Non è richiesto un preventivo economico, una tariffa
oraria o una ricevuta di costo. Registrare il termine massimo autorizzato e
chi spegne il pod; verificare l'accesso al comando/API di arresto e confermare
lo stato finale dal provider. Un timeout del processo non spegne il pod.
I flag `--stop-after`/`--terminate-after` rimossi da `runpodctl` restano
inaffidabili: il [record storico](../../benchmarks/results/c71-runpod-deadline-audit-2026-10-03-5fba934b009f.json)
conserva quel fallimento, senza imporre un nuovo gate economico.

**Campagna corrente (4 ottobre 2026).** Pod `z3h2njpctmduix`, H100;
ambiente, parità CUDA, download necessari, calibrazione e diagnostica
O=0/150/300 autorizzati. Il lavoro iniziato alle 17:07:53 UTC termina
entro le 23:07:53 UTC (6 h), senza proroga; almeno gli ultimi 30 minuti
sono riservati a salvataggio e chiusura. Lo spegnimento è gestito dall'agente.
La destinazione esterna autorizzata è
`/home/okrame/projects/volta-zk/artifact/c7.1-pod/`, con **tetto complessivo
10.000.000.000 B**. Conservare calibrazione verificata, ricette/tabelle,
identità/hash, codice/ambiente, report, log e manifest; non copiarvi shard,
packed o tracce grandi. I pesi vengono ricreati sul pod a ogni campagna e
verificati contro le stesse identità. La calibrazione completata resta
riutilizzabile secondo i controlli sotto; una nuova H100 richiede comunque
compatibilità, parità e nuove misure fisiche.

**Esito acquisito.** Il [primo trial di parità](../../benchmarks/results/c71-h100-first-parity-failure-2026-10-04-d4abed66fc41.json) sulla SHA
pulita `d4abed66` è **FAIL**, exit 1, `CUDA: invalid argument`.
La build mirata è passata. Il primo bundle immutabile verificato è
`artifact/c7.1-pod/first-failure-20261004T174606Z/`, circa 100 MB, con
manifest, codice Git, eseguibili, ambiente e log; non contiene pesi,
calibrazione o tracce private. Il massimo RSS+HBM campionato è
99.942.400 B, con margine campionato 6.342.508.544 B sul tetto; picco
fisico completo e margine canonico restano **non verificati**. Le fasi
dipendenti non sono partite. Una correzione della fixture Gate è pronta
nel commit `65b5fe7`, verificata solo su host; il nuovo trial attende
l'autorizzazione esplicita all'eccezione di retry entro la scadenza originale.
La pausa temporaneamente richiesta per aggiornare macOS è stata revocata:
il pod continua e il controllo locale di spegnimento è stato riattivato.

| Passaggio | Stato e condizione di uscita |
|---|---|
| Preparazione locale | 13 producer CUDA, scanner, registro e runner misto implementati; compilazione sm_90, schedule canonica e test numerici/protocollo ridotti. Nessun W reale o dominio D34/D35 eseguito localmente |
| Calibrazione autorizzata | Driver indipendente disponibile; confronto sui pesi reali, due replay e Γ validato da acquisire. I comandi CPU seguenti non sono il benchmark della prova |
| Primo esperimento della prova | Parità dei kernel reali, smoke fail-closed e tre tentativi O=0/150/300 sul runner misto; raccogliere tempi, memoria/trasferimenti e anche timeout/rifiuti |
| Valutazione | Distinguere risultato misurato, obiettivi mancati e assunzioni aperte. Nessun risultato locale promette 65 s, 40 MB o picco fisico completo |

Il checkpoint preliminare registra PASS, FAIL o INCOMPLETO per ciascuna
fase richiesta, con copertura e limiti. Un bundle salvato non rende PASS
una calibrazione fallita; una misura parziale non chiude il picco completo.

Il comando di riferimento rimane
`c71_canonical_reference reference-cpu CANDIDATE TABLES PACKED NEW_JOURNAL_DIRECTORY PREPARATION_BYTES`.
Il comando GPU e il monitor sono nella
[procedura dell'esperimento](#esperimento-della-prova).
Entrambi usano prompt pinned e journal nuovi, senza ripristino/sovrascrittura.
`PREPARATION_BYTES` non è un limite globale. Non eseguirli sulla VM locale.
Errore o timeout termina il singolo run; retry e nuovi journal richiedono
autorizzazione corrente. I successivi trial sono preautorizzati in questa
campagna, sempre da O=0 e senza riuso delle correlazioni. Nessuna proroga
o fallback è inclusa.

La [contabilità](specs.md#runner-cuda-sperimentale-e-conto-simultaneo)
espone W host/device, arena e suoi payload, staging e fasi CPU residue.
I contatori CUDA sono cumulativi sullo stesso owner e non si sommano.
RSS/HWM riguarda i due ruoli nello stesso processo. Il report distingue
inferenza con cattura dello stato dal resto della risposta e conserva
`C71_RUN_METRICS` su errore gestito; timeout/kill richiedono log esterni.
`complete_physical_peak:false` non nasconde lo scratch ancora CPU.

Il diagnostico [c71_nonlinear_parity.cu](../../cuda/c71_nonlinear_parity.cu)
confronta kernel reali con interi host: dense MMA su tre shape (ragged e
K=21504), Affine/Gate, tutti i 65.535 entry lookup, istogrammi, entrambe
le famiglie RoPE, argmax/tie, RMS/overflow e QK→RNE→EXP30→PV nei tre
contesti con futuro KV avvelenato. QK/PV sono interi scalari, non MMA.
Si compila localmente; si esegue soltanto nel primo esperimento autorizzato:

```bash
nvcc -std=c++17 -O2 -arch=sm_90 --cudart static \
  cuda/c71_nonlinear_parity.cu cuda/c71_dense_i16.cu \
  -o /tmp/c71_nonlinear_parity
timeout -k 5s 60s /tmp/c71_nonlinear_parity
```

Richiede compute capability 9; errore CUDA o differenza termina con exit
nonzero. Conservare stdout/stderr, digest del binario, SHA e fingerprint.
È parità sintetica `credit:false`, non un forward canonico o un benchmark.
Il test seguente è ignorato nelle suite locali e usa **la libreria reale**,
non il driver simulato: verifica gather residente→range/GKR→PCS sui MAC
originali due volte nello stesso owner, poi range signed, contro transcript
CPU ridotti. Eseguirlo sulla H100 dopo aver impostato il binario appena
compilato e `LIBRARY` alla libreria CUDA della stessa SHA:

```bash
C71_NATIVE_PARITY_LIBRARY="$LIBRARY" timeout -k 5s 60s "$C71_PCS_TEST_BINARY" \
  c71_b12_windowed_native_hardware_parity_explicit --ignored --test-threads=1 --nocapture
```

Non richiede pesi reali; la sua disponibilità non dichiara già passata
la parità hardware. Il test locale equivalente usa lo stesso helper con
driver host simulato e non viene contato come esecuzione GPU.
Le procedure delle sezioni seguenti regolano soltanto campagne autorizzate.
Prima di usare credenziali locali eseguire
`scripts/runpod_harness.sh local-secret-preflight`. Un eventuale `.env`
deve essere un file regolare posseduto dall'utente e avere permessi `0600`;
il controllo non lo carica e non stampa nomi o valori.

## Gestione del pod e del repository

Usare [runpod_harness.sh](../../scripts/runpod_harness.sh) per la gestione
di un eventuale pod autorizzato. Il harness permette ispezione e chiusura,
ma non sostituisce il termine massimo e la responsabilità di arresto sopra. Non sono impliciti
retry, proroghe o una seconda macchina. Prima di compilare o generare
artefatti eseguire `scripts/runpod_harness.sh git-preflight`, oppure verificare
lettura/scrittura Git HTTPS dalla VM, pubblicare la SHA su un branch unico
e verificare dal pod il checkout anonimo pulito di quella stessa SHA.
Questa alternativa conserva le credenziali sulla VM e pubblica le evidenze
piccole dalla VM dopo il trasferimento del bundle autorizzato.

Sincronizzare repository ed evidenze piccole solo tramite Git HTTPS su
`https://github.com/okrame/volta-zk.git`. Le sorgenti pubbliche si leggono
anonimamente. Per pubblicare dal pod usare il Secret RunPod `VOLTA_GITHUB_TOKEN`,
con scadenza e permesso Contents read/write limitato al repository.
Non copiare credenziali dalla VM, non usare gh, Git SSH, SCP/rsync o
archivi del repository per sincronizzare il codice. Il bundle autorizzato
può essere trasferito via SSH alla destinazione persistente entro il suo
tetto; le evidenze piccole revisionate sono poi pubblicate tramite Git HTTPS. Token fuori da URL, configurazioni Git, comandi,
cronologia e file; il wrapper usa askpass. Un eventuale Secret HF è
separato e di sola lettura. Verificare la SHA pulita dopo ogni pull.

```text
scripts/runpod_harness.sh list
scripts/runpod_harness.sh status POD_ID
scripts/runpod_harness.sh pause POD_ID
scripts/runpod_harness.sh delete POD_ID --confirm POD_ID
```

`pause` lascia storage fatturabile. `delete` termina il pod e distrugge
i dati sul volume locale: prima verificare la pubblicazione delle evidenze
piccole e l'eventuale conservazione dei dati in una destinazione autorizzata.
Pesi e grandi artefatti non vanno in Git; per conservarli dopo la chiusura
serve la destinazione persistente autorizzata.
La pubblicazione usa un branch unico tramite `git-push runpod/POD_ID/LABEL`.

## Campagna di calibrazione

La procedura valuta una sola candidata Γ. Registrare SHA pulita,
immagine/container con digest, hardware e limiti autorizzati. Nessuna
modifica delle scale o ripartenza è inclusa; il completamento dei test
non deroga al termine massimo.

I programmi esistenti usano NumPy/BLAS CPU per l'inizializzatore e il
confronto indipendente, Rust CPU per il replay intero e un piccolo kernel C
CPU per RMS; non esiste una calibrazione CUDA completa.
Un host CPU equivalente è l'alternativa meno costosa da concordare nella
stessa decisione operativa. `nvidia-smi` non accelera questi comandi.
Inferenza BF16, TF32 o Transformers non sostituisce la relazione intera.

Il tempo completo non è misurato. L'inizializzatore conta
13.390.420.377.600 prodotti di matrice e 26.782.043.904.000 B di letture W
logiche, che non sono traffico fisico o tempi H100. Alla deadline si
conserva il fallimento e si termina, senza dichiarare Γ calibrato.
L'ammissione di Γ richiede tutti i controlli della
[validazione](#validazione-e-congelamento-del-profilo), incluso il confronto
indipendente; tempo e risorse del confronto rientrano nella campagna.

### Risorse

| Risorsa | Richiesta proposta / controllo prima del download |
|---|---|
| Compute | 1 H100 SXM 80 GB, almeno 20 vCPU e 125 GB RAM host; verificare l'offerta effettiva |
| Software | Linux x86_64, Python ≥3.11, NumPy, pytest, Rust/Cargo, C/C++ build tools, Git, GNU timeout/time; versioni e immagine registrate |
| Disco | Volume locale 300 GB montato in `/workspace`, container 40 GB; almeno 180 GB liberi prima del download |
| Payload sul pod | Shard 62.546.338.248 B + packed 61.394.690.560 B = 123.941.028.808 B |
| Temporanei | Download direttamente in `.partial`, rinomina senza seconda copia; packed e traccia pubblicati atomicamente; nessuna seconda copia BF16/dequantizzata completa |
| Memoria | Ingest nativo richiede 3.355.443.200 B operativi; trial con payload nominato ≤8 GiB; limite AS per processo 64 GiB; osservare anche RSS aggregato/cgroup e cache OS |
| Numerica | Pilot: blocco W i16+f64 ≤27.525.120 B, KV finale f64 1.622.016.000 B; replay KV finale i16 405.504.000 B, più A viva, tabelle, workspace e runtime |
| Traccia privata | Riservare 44 GB per il primo replay: limite conservativo da A nei codec originali, KV finale e framing; il padding è compattato. Resta fuori da Git e rientra nei limiti di disco e tempo |

Questi limiti riguardano la calibrazione offline, non il budget dei
temporanei della prova. I payload non sono un picco RSS completo. Stop per OOM, swap
sostenuto, RSS aggregato >96 GiB o spazio libero <20 GB; non aumentare
i budget per aggirare un fallimento. Il requisito legacy 256 GiB/400 GB
del pack Python non si applica al `pack --native-packer`: non usare i
subcomandi legacy `preflight`/`report` per ammettere questa macchina.
Il pack nativo verifica già header, entrambi i corpi e output persistito.

### Budget delle fasi

Registrare il termine complessivo autorizzato in `AUTHORIZED_END_EPOCH`.
I timeout degli snippet sono massimi per fase, non una stima del tempo
completo né un'autorizzazione a prolungare la campagna. Fissare `TRACE_STEP_SECONDS` e
`NATIVE_TRACE_TIMEOUT_SECONDS` includendo il confronto indipendente,
ancora non misurato sui pesi reali. Ogni fase deve rientrare nel tempo
residuo, con almeno 30 minuti riservati a conservazione e chiusura.
I timeout esterni coprono anche hash e generazione tabelle. Al primo
errore si saltano le fasi dipendenti di quel trial e si conserva il fallimento;
un trial successivo preautorizzato richiede nuovi file e prerequisiti risolti;
la chiusura concordata non si rinvia per completare o salvare un run.

### Identità degli input

Usare esclusivamente [checkpoint, shard, digest e workload delle specifiche](specs.md#input-e-identità),
mai `main`. I comandi importano le stesse costanti da
[c7_d126_gemma_weight_ingest.py](../../scripts/c7_d126_gemma_weight_ingest.py).
Nessun dataset nuovo, imposizione dei token prodotti dal pilot floating
o certificazione di qualità generale. Accesso HF/licenza deve essere già
valido; un 401/403 ferma la fase, senza accettare licenze o cambiare checkpoint.

### Comandi dopo autorizzazione esplicita e risoluzione dell'hard stop

Gli snippet seguenti **non sono stati eseguiti sui pesi reali**. Prima
fissare `APPROVED_SHA`, `AUTHORIZED_END_EPOCH`, `TRACE_STEP_SECONDS` e
`NATIVE_TRACE_TIMEOUT_SECONDS`. Usare il pod autorizzato e i Secret della
[procedura di gestione](#gestione-del-pod-e-del-repository).

```bash
set -euo pipefail
set -C
umask 077
git clone https://github.com/okrame/volta-zk.git /workspace/volta-zk
cd /workspace/volta-zk
git checkout --detach "$APPROVED_SHA"
scripts/runpod_harness.sh git-preflight
export ROOT=$PWD
export RUN=/workspace/c71-gamma-$(date -u +%Y%m%dT%H%M%SZ)
mkdir "$RUN"
mkdir "$RUN/logs" "$RUN/weights"
export SHARDS="$RUN/weights"
export PACKED="$SHARDS/gemma-4-31b-5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89.packed.i16"
export CARGO_TARGET_DIR="$ROOT/rust/target" CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_DEV_OPT_LEVEL=2
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 RAYON_NUM_THREADS=1
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$ROOT/scripts"
test "${AUTHORIZED_END_EPOCH:?termine autorizzato richiesto}" -gt "$(date +%s)"
export CAMPAIGN_END_EPOCH=$((AUTHORIZED_END_EPOCH - 1800))
ulimit -v 67108864
run_step() {
  local seconds=$1 label=$2 code
  shift 2
  test $(( $(date +%s) + seconds )) -le "$CAMPAIGN_END_EPOCH"
  test ! -e "$RUN/logs/$label.stdout"
  date -u +%FT%TZ > "$RUN/logs/$label.start"
  set +e
  /usr/bin/time -v timeout -k 30s "${seconds}s" "$@" \
    > "$RUN/logs/$label.stdout" 2> "$RUN/logs/$label.stderr"
  code=$?
  set -e
  printf '%s\n' "$code" > "$RUN/logs/$label.exit"
  date -u +%FT%TZ > "$RUN/logs/$label.end"
  test "$code" -eq 0
}
```

Non rilanciare lo stesso label/directory. Anche un timeout prima che il
wrapper produca JSON conserva stdout, stderr ed exit code; non trattare
un file vuoto/troncato come risultato. Il termine autorizzato prevale sul
controller locale. Preparare venv/toolchain nella fase ambiente, senza
upgrade non registrati; `pip freeze`, `rustc -Vv`, `cargo -V`, `uname -a`,
termine/responsabile di arresto, CPU/RAM/disco e SHA immagine vanno nei log.

```bash
run_step 240 venv python3 -m venv .venv
run_step 300 dependencies .venv/bin/python -m pip install numpy==2.5.1 pytest==9.1.1
run_step 1800 build bash -c '
  set -euo pipefail
  cd "$ROOT/rust"
  cargo fetch --locked
  cargo build --offline --locked -j 1 -p volta-pcs \
    --features c71-b12-pcs --example c71_calibration
  cd "$ROOT"
  rustc --edition 2021 -O rust/volta-pcs/examples/gemma31b_bf16_pack.rs \
    -o "$CARGO_TARGET_DIR/gemma31b_bf16_pack"
'
export NATIVE="$CARGO_TARGET_DIR/debug/examples/c71_calibration"
export C71_CALIBRATION_BINARY="$NATIVE"
run_step 60 describe "$NATIVE" describe
run_step 60 pilot-plan .venv/bin/python scripts/c71_activation_pilot.py plan --native "$NATIVE"
(ulimit -v 2097152; run_step 60 calibration-checks .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_c71_calibration.py)
(ulimit -v 2097152; run_step 60 trace-checks .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_c71_calibration_trace.py)
(ulimit -v 2097152; run_step 60 pilot-checks .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_c71_activation_pilot.py)
(ulimit -v 2097152; run_step 60 native-ingest-checks .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_c7_d126_gemma_native_bf16.py)
(ulimit -v 2097152; run_step 60 ingest-checks .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_c7_d126_gemma_weight_ingest.py)
```

La venv e le versioni dei pacchetti devono essere predisposte nella fase
ambiente; i comandi assumono `.venv/bin/python` con NumPy e pytest già
verificati. Non copiare la venv locale o credenziali al pod. Una build
priva delle dipendenze native non autorizza un altro pod:
fermare nella fase ambiente. I controlli piccoli mantengono 60 s / 2 GiB
e un worker. Su questo host a 224 CPU visibili, il linker LLVM dei piccoli
test Rust richiede anche affinità a un solo core (`taskset -c CPU`): senza
questa, la creazione dei thread fallisce sotto il limite AS. Il trial
fallito resta conservato; l'affinità non aumenta il budget; non sostituiscono i trial reali. Non eseguire workspace E2E.

### Download e ingest

Download anonimo ove consentito; l'eventuale Secret è letto solo in
memoria. Un solo tentativo, nessuna ripresa automatica di partial.

```bash
run_step 1800 download .venv/bin/python - <<'PY'
import hashlib
import os
from pathlib import Path
import urllib.parse
import urllib.request
from c7_d126_gemma_weight_ingest import MODEL, REVISION, SHARDS
class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        redirected = super().redirect_request(request, response, code, message, headers, url)
        if redirected and urllib.parse.urlsplit(request.full_url).netloc != urllib.parse.urlsplit(url).netloc:
            redirected.remove_header('Authorization')
        return redirected
opener = urllib.request.build_opener(SafeRedirect())
for name, spec in SHARDS.items():
    target = Path(os.environ['SHARDS']) / name
    partial = target.with_suffix(target.suffix + '.partial')
    assert not target.exists() and not partial.exists()
    request = urllib.request.Request(f'https://huggingface.co/{MODEL}/resolve/{REVISION}/{name}')
    if os.environ.get('HF_TOKEN'):
        request.add_header('Authorization', 'Bearer ' + os.environ['HF_TOKEN'])
    digest = hashlib.sha256()
    count = 0
    with opener.open(request, timeout=60) as source, partial.open('xb') as sink:
        while chunk := source.read(4 * 1024**2):
            count += len(chunk)
            assert count <= spec['bytes']
            digest.update(chunk)
            sink.write(chunk)
        sink.flush()
        os.fsync(sink.fileno())
    assert count == spec['bytes'] and digest.hexdigest() == spec['lfs_sha256']
    os.link(partial, target)
    partial.unlink()
    print(name, count, digest.hexdigest(), flush=True)
PY
run_step 1800 ingest .venv/bin/python scripts/c7_d126_gemma_weight_ingest.py pack \
  --shard-dir "$SHARDS" --output "$PACKED" \
  --native-packer "$CARGO_TARGET_DIR/gemma31b_bf16_pack"
export INGEST="$RUN/logs/ingest.stdout"
chmod a-w "$SHARDS"/*.safetensors "$PACKED"
```

Successo: `PACKED_UNADMITTED`, `full_source_bodies_verified:true`, due
hash completi esatti, 772 esponenti minimi RNE-fit, packed della lunghezza
attesa e hash del file persistito. Il nome UNADMITTED è corretto: ingest
non equivale a calibrazione o installazione crittografica. Preservare
failure/partial senza ripararle in loco o cancellare l'evidenza.

### Pilot, tabelle e due replay interi

```bash
run_step 5400 pilot .venv/bin/python scripts/c71_activation_pilot.py run \
  --native "$NATIVE" --ingest-report "$INGEST" --packed "$PACKED" \
  --output "$RUN/pilot" --timeout-seconds 5100
export CANDIDATE="$RUN/pilot/candidate.json"
chmod a-w "$CANDIDATE"
run_step 60 recipes "$NATIVE" recipes "$CANDIDATE"
run_step 900 tables .venv/bin/python scripts/c71_calibrate.py tables \
  --native "$NATIVE" --candidate "$CANDIDATE" --output "$RUN/tables.bin"
run_step 60 check-input "$NATIVE" check-input "$CANDIDATE" "$RUN/tables.bin"
test -n "${TRACE_STEP_SECONDS:-}" && test -n "${NATIVE_TRACE_TIMEOUT_SECONDS:-}"
run_step "$TRACE_STEP_SECONDS" integer-1 .venv/bin/python scripts/c71_calibrate.py trace \
  --native "$NATIVE" --candidate "$CANDIDATE" --ingest-report "$INGEST" \
  --packed "$PACKED" --output "$RUN/integer-1.json" \
  --trace-output "$RUN/integer-1.trace" \
  --payload-bytes 8589934592 --timeout-seconds "$NATIVE_TRACE_TIMEOUT_SECONDS"
run_step 5400 integer-2 .venv/bin/python scripts/c71_calibrate.py run \
  --native "$NATIVE" --candidate "$CANDIDATE" --ingest-report "$INGEST" \
  --packed "$PACKED" --output "$RUN/integer-2.json" \
  --payload-bytes 8589934592 --timeout-seconds 5100
run_step 900 ledger .venv/bin/python scripts/c71_calibrate.py ledger \
  --native "$NATIVE" --candidate "$CANDIDATE" --output "$RUN/ledger.json"
```

Le due invocazioni ripartono ciascuna da KV vuoto; all'interno collegano
O=0/150/300 senza importare stato. Il secondo replay verifica
riproducibilità del riferimento, **non** è una seconda implementazione
indipendente. Il primo replay pubblica `C71TRC01` solo dopo exit 0,
validazione strutturale e confronto esatto col driver indipendente, con
permessi `0600`; la traccia contiene valori privati e non entra
nel bundle Git. I 150 token floating non sono il golden intero. Una
candidata che non compila o produce overflow/range failure richiede
stop per quel trial; una revisione delle scale comporta nuova candidata e
ripartenza da O=0, mai riparazione del solo contesto fallito. La preautorizzazione
corrente copre i nuovi trial entro gli stessi limiti, senza cambiare la relazione,
il trust model o i requisiti di validazione.

### Validazione e congelamento del profilo

Prima di congelare verificare, sui file persistiti e non sul solo exit 0:

1. Identità shard/packed/ingest/workload/native e SHA pulita invarianti;
   `pilot/report.json` completo, `success:true`, `candidate_compiles:true`.
2. Stessa mappa W/A completa e stesse ricette nei tre contesti; tabelle
   certificate rigenerate con Python, 24.414.870 B, SHA-256 identico fra
   `tables`, entrambi i replay e conto delle risorse, più digest nativo coerente.
3. Entrambi i report con `complete_integer_trial:true`, `exit_code:0`,
   `native_exit_code:0`, `packed_hash_checked:true`,
   `tables_generated_by_certified_reference:true`. Tre `responses`,
   O=0/150/300, 150 token ciascuna, prefisso esatto dei 100 token pinned,
   50 output validi; extents/copertura di ogni ID A e contatori completi.
4. `responses` identiche fra i due replay, inclusi token, extents e lavoro;
   nessun overflow, non-finito, saturazione, marker di errore o trial
   parziale. Il controller deve avere assorbito l'ultimo token in KV;
   non inferirlo dalla sola lunghezza della lista dei token.
5. Confronto indipendente completato secondo il
   [contratto delle specifiche](specs.md#confronto-indipendente).
   L'export `C71TRC01`, il validatore strutturale e il piano pubblico
   canonico validato sono disponibili; il wrapper lega inoltre le forme
   specifiche di O=0/150/300 al piano. Il produttore numerico indipendente
   è disponibile ma deve risultare `complete:true` sui pesi reali. Min/max, censimenti
   e un secondo replay Rust non lo sostituiscono; non inventare un comando
   `freeze` o un confronto bit per bit mai eseguito.

Il piano conserva quindi due esiti distinti: bundle numerico riproducibile
ottenibile con i comandi correnti, e **Γ ammesso/congelato** soltanto dopo
tutti e cinque i controlli. «Candidata validata dal riferimento» descrive
il primo esito: non è un campo JSON né una ricevuta di ammissione.
Non si cambia un `calibrated:false` prodotto dai tool in `true` a mano.
La ricevuta di ammissione deve referenziare i cinque controlli, la copertura
esatta e ogni assunzione residua; in sua assenza l'ammissione resta aperta.

Conservare in una nuova directory immutabile, senza aggiornare i manifest
storici: candidata, descrizione ID, report ingest/pilot, ricette e digest
tabelle, entrambi i report interi, eventuali golden/audit, conto delle risorse,
toolchain/image/SHA, termine e arresto verificato, comandi, stdout/stderr,
exit, tempi e RSS. Il manifest nuovo elenca path relativi, byte e
SHA-256 di ciascun file; hash anche del manifest, scrittura esclusiva e
lettura di verifica. Le tabelle possono essere rigenerate dai digest e
ricette; i dump privati richiedono storage autorizzato e non entrano in Git.

```bash
.venv/bin/python - <<'PY'
import hashlib
import json
import os
from pathlib import Path
root = Path(os.environ['RUN'])
manifest = root / 'files.json'
seal = root / 'files.json.sha256'
assert not manifest.exists() and not seal.exists(), 'new bundle required'
def describe(path):
    with path.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
        size = os.fstat(source.fileno()).st_size
    return {'path': path.relative_to(root).as_posix(), 'bytes': size, 'sha256': digest}
files = [describe(path) for path in sorted(root.rglob('*'))
         if path.is_file() and 'weights' not in path.relative_to(root).parts]
with manifest.open('x') as sink:
    json.dump(files, sink, indent=2, sort_keys=True)
    sink.write('\n')
with seal.open('x') as sink:
    sink.write(describe(manifest)['sha256'] + '  files.json\n')
assert json.loads(manifest.read_text()) == files
assert all(describe(root / row['path']) == row for row in files)
assert seal.read_text() == describe(manifest)['sha256'] + '  files.json\n'
PY
```

Eseguire solo a produttori e log chiusi; dopo il manifest non modificare
i file censiti. I pesi sono esclusi dalla lista e identificati dal report
ingest. Il manifest non include se stesso né il proprio digest. Un errore
lascia il bundle incompleto: non ripararlo sovrascrivendolo. Il bundle in Git usa
solo la selezione piccola revisionata, non `git add "$RUN"`. Un record
nuovo va in `benchmarks/results/c71-calibration-DATE-GITSHA.json`, con
`git_dirty:false` riferito al codice eseguito, esito e digest degli output.
Prima del push copiare nel repository soltanto la selezione piccola,
controllare che non contenga segreti o valori privati, aggiungere i singoli
file espliciti e creare un commit delle evidenze. `git-push` pubblica
commit esistenti: non raccoglie automaticamente i file di RUN.
Pubblicare secondo la procedura RunPod in un branch unico:

```bash
scripts/runpod_harness.sh git-preflight
scripts/runpod_harness.sh git-push "runpod/$RUNPOD_POD_ID/c71-gamma"
```

Alla chiusura della campagna, verificare da un checkout remoto separato
il commit e i file pubblicati, e la destinazione autorizzata dei dati da
conservare, prima del `delete` della [gestione pod](#gestione-del-pod-e-del-repository).
Resta vincolante il termine concordato, anche se il salvataggio è incompleto.
Dopo l'ammissione di Γ, portare profilo e conto delle risorse
all'[esperimento della prova](#esperimento-della-prova) se già autorizzato
e compatibile con il budget residuo. La calibrazione non misura prova/PCG
e non emette certificati.

Per riusare il bundle in una nuova campagna, verificarne manifest e hash
dalla destinazione persistente e confrontare modello/packed, workload,
Γ, tabelle e ricette con le identità validate. Registrare il record di
provenienza: si possono saltare le fasi numeriche già validate se codice
e ambiente pertinenti sono invariati, oppure dopo una verifica documentata
dell'impatto delle differenze. Un bundle parziale conserva solo il credito
delle fasi completate. Hash e ricette non conservano da soli il packed: nella campagna corrente
si conservano identità ed esponenti, si ricreano i pesi sul nuovo pod e si
richiede nuovamente il confronto esatto dell'hash packed con quello validato.
Sulla nuova H100 verificare ambiente e parità; picchi fisici e tempi
richiedono nuove misure. Correlazioni monouso, journal e KV di sessione
non sono cache da importare nella nuova esecuzione.

## Esperimento della prova

Il comando è ora `c71_canonical_reference experiment-cuda`. Gli esempi
`c71_matrix` e `c71_calibration` non lo sostituiscono. L'esperimento usa
la pipeline mista dichiarata, senza presentare la PCS CPU come GPU.
Il [checkpoint locale](../../benchmarks/results/c71-device-runner-local-2026-10-04-1ec6720bb494.json)
conserva la SHA eseguibile e i digest. Usare le
[build mirate](local-tests.md#compilazione-mirata) e la
[build della libreria CUDA](local-tests.md#collegamento-del-runner-cuda).
La campagna segue la riduzione locale del budget comune descritta nelle
[specifiche](specs.md#runner-cuda-sperimentale-e-conto-simultaneo). Il limite
imposto alle allocazioni è 5.905.580.032 B; la riserva fisica dichiarata è
256 MiB e il margine richiesto altri 256 MiB. Prima di concedere credito,
misurare insieme host e device durante O=0/150/300: includere capacità
libere trattenute, context/driver, stack kernel, staging e socket. Richiedere
zero rifiuti di allocazione, completamento/verifica/promozione e overhead
entro la riserva; un abort al tetto non è una prova che il caso canonico
rientra. La parità CUDA, i tempi e il traffico completi restano verifiche
fisiche. Il raggruppamento dei coset introduce accumulazioni aggiuntive:
non riusare i vecchi upper temporali o dare credito al lavoro non crescente.

Per istruzione del proprietario, parità hardware, tempo H100 e picco fisico
si verificano **nel primo esperimento**, non sono gate locali. Il vecchio
gate di compatibilità preventiva con 65 s non blocca questo esperimento
diagnostico: misurare e conservare anche il mancato target. Rimangono
invariati NoPeek, MAC originali, margine arena 256 MiB, margine globale
1 GiB e stop su esaurimento senza spill dinamico.

Gli esperimenti GPU confrontano prima gli operatori con il diagnostico
di parità sopra e il range con il riferimento host/nativo. FFT, resti/PQ
e hash salato sono ancora CPU in questo runner; non rivendicare la loro
accelerazione. Poi si misurano le fasi rappresentative con i
loro stati simultaneamente vivi. Un kernel veloce da solo non dimostra
il tempo completo. CUDA richiesto ma non disponibile deve produrre errore,
senza un percorso CPU sostitutivo. La produzione usa PCG reale/AES.

Comando sul solo hardware autorizzato, dopo ammissione di Γ, build e
parità, entro il budget residuo con la riserva di chiusura. Impostare
`APPROVED_SHA`, `PROOF_SECONDS`, `CANDIDATE`, `TABLES`, `PACKED`, `LIBRARY`
e `RUN` (directory nuova sotto `benchmarks/raw`). Il device logico è 0;
fissare prima `CUDA_VISIBLE_DEVICES` all'UUID autorizzato. I limiti di
durata del processo non sostituiscono lo spegnimento entro il termine massimo.

```bash
set -euo pipefail
set -C
umask 077
test "$(git rev-parse HEAD)" = "$APPROVED_SHA"
test -z "$(git status --porcelain --untracked-files=all)"
test "$PROOF_SECONDS" -gt 0
mkdir "$RUN"
nvidia-smi -q > "$RUN/hardware.txt"
nvcc --version > "$RUN/nvcc.txt"
rustc -vV > "$RUN/rustc.txt"
sha256sum "$LIBRARY" rust/target/debug/examples/c71_canonical_reference \
  > "$RUN/executables.sha256"
nvidia-smi --query-gpu=timestamp,uuid,memory.total,memory.used,memory.free,utilization.gpu \
  --format=csv -l 1 > "$RUN/gpu.csv" 2> "$RUN/gpu-monitor.stderr" &
MONITOR_PID=$!
trap 'kill "$MONITOR_PID" 2>/dev/null || true; wait "$MONITOR_PID" 2>/dev/null || true' EXIT
set +e
/usr/bin/time -v -o "$RUN/process-time.txt" \
  timeout -k 5s "$PROOF_SECONDS" \
  rust/target/debug/examples/c71_canonical_reference experiment-cuda \
  "$CANDIDATE" "$TABLES" "$PACKED" "$RUN/journals" 2147483648 "$LIBRARY" 0 \
  > "$RUN/runner.json" 2> "$RUN/runner.stderr"
STATUS=$?
set -e
printf '%s\n' "$STATUS" > "$RUN/exit-code.txt"
exit "$STATUS"
```

Il monitor nvidia-smi osserva il device intero, non attribuisce memoria a
un ruolo; un monitor fallito invalida la misura HBM, non autorizza una
stima nulla. `time -v` registra CPU-time/RSS del processo con entrambi i
ruoli. Il timeout registra un fallimento anche se manca JSON finale.
Al primo errore numerico, parity, verifica, OOM o timeout non proseguire
il run fallito. La preautorizzazione dei trial successivi non permette
prosecuzione/importazione dello stato terminale o riuso di correlazioni.
Una conclusione positiva richiede `canonical_certificates_verified:3`,
tre `accepted:true`, ledger/cleanup validi e stesso head dei journal.
I report mantengono `credit:false` e le assunzioni aperte: non sono
certificazione automatica di Γ o del target. Pubblicare un nuovo record
`benchmarks/results/c71-cuda-experiment-DATE-GITSHA.json` con comandi,
exit code, fingerprint, digest dei log e limiti; mai sovrascrivere evidenza.

Il risultato completo richiede tre risposte valide del modello canonico,
stesso W e storia KV, con tempi e byte completi del [contratto](design.md#contratto-delle-risorse).
Registrare separatamente `T_inference`, `T_proof_only`, `T_response_total`,
setup di sessione e caricamento globale, traffico nei due sensi, tutti i
batch/replay, picchi allocati e riservati del prover e del verificatore.
Non sottrarre il lavoro dipendente dalla risposta o attribuire overlap
senza misura. Il limite inferiore dei byte delle continuazioni è già
incompatibile con 40 MB per il codec corrente: riportare l'esito analitico
ammesso, senza etichettarlo come successo misurato di quel requisito.

Conservare nuovi record anche per timeout, errori numerici, esaurimento,
fallimenti di verifica o risultati oltre i limiti. La SHA del codice
eseguito deve essere pulita. I record non autorizzano nuovi tentativi; la preautorizzazione corrente
del proprietario copre i successivi trial entro il termine originale;
aggiornare i cinque documenti correnti solo quando cambia un fatto,
collegando la nuova evidenza senza sovrascrivere quella precedente.

Il [record locale a SHA pulita 82dae48](../../benchmarks/results/c71-temporary-memory-local-2026-10-04-82dae4818962.json) conserva 41 test Rust
e 11 Python passati, build lib/runner/sm_90, ledger, hash e fallimenti
intermedi. Un test GPU resta intenzionalmente ignorato. Non acquisisce
W reale, esecuzione canonica o conformità fisica H100.
