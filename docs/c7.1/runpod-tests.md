# C7.1 — test su RunPod

[Design](design.md) · [Specifiche](specs.md) · [Sicurezza](security.md) ·
[Test locali](local-tests.md) · [Archivio](../c7.1-history/README.md)

## Stato e sequenza operativa

Non è registrata un'autorizzazione a download dei pesi, creazione di pod,
esecuzioni GPU o spesa. Il lavoro locale pertinente resta autorizzato.
Il [readiness audit v6 di partenza](../../benchmarks/results/c71-h100-e2e-readiness-2026-10-03-fbd6141e7a1e.json)
ha esito `NOT_READY`. Il riferimento CPU ora collega prover canonico,
getter e registro, ma non dispone di certificati canonici validi acquisiti
né dell'esecuzione a memoria limitata su GPU. Non
avviare la campagna provider sulla sola base dei controlli locali passati.
La calibrazione e il benchmark della prova sono due campagne distinte:
un successo numerico non autorizza né dimostra il secondo.

**Hard stop provider (3 ottobre 2026).** `runpodctl` v2.12.0 ha rimosso
`--stop-after` e `--terminate-after`: il backend li accettava ma non li
eseguiva, quindi il pod restava attivo e fatturabile oltre la scadenza.
La [correzione ufficiale](https://github.com/runpod/runpodctl/commit/51ca7f0)
dichiara che non esiste un sostituto finché il backend non applica la
deadline. Non creare il pod H100 finché una deadline provider verificabile
o un diverso limite di spesa autorizzato non chiude questo rischio.
Il [record immutabile](../../benchmarks/results/c71-runpod-deadline-audit-2026-10-03-5fba934b009f.json)
conserva la fonte upstream e i controlli locali.

Leggere prima [design](design.md), poi le sezioni pertinenti di
[specs](specs.md) e [security](security.md). Questa pagina definisce la
sequenza operativa e lo stato delle implementazioni; [local-tests](local-tests.md)
definisce i controlli piccoli. Non occorre recuperare istruzioni dall'archivio.

| Ordine | Disponibile | Lavoro e condizione di uscita |
|---|---|---|
| 1. Preparare il confronto, localmente | Ingest W, inizializzatore delle scale, tabelle certificate, replay intero CPU, export `C71TRC01`, piano pubblico canonico e driver indipendente testato sui 13 operatori e sulla schedulazione completa | Eseguire e misurare il [confronto indipendente](specs.md#confronto-indipendente) sui pesi reali. Il runtime completo è ignoto e la finestra corrente di 8 ore non è ancora chiusa |
| 2. Calibrare i pesi reali, dopo autorizzazione | Comandi CPU nelle sezioni seguenti; nessuna calibrazione CUDA completa | Una sola candidata, due replay e confronto indipendente nei tre contesti; soddisfare la [validazione](#validazione-e-congelamento-del-profilo), quindi fissare Γ e ricompilare il conto delle risorse |
| 3. Integrare la prova, prima su input ridotti | Prover e getter CPU canonici collegati al registro e al completamento autenticato dal canale; test ridotti e controlli canonici di rifiuto | Acquisire certificati canonici validi e verificare tutte le componenti sullo stesso registro; i test ridotti non provano la correttezza del percorso completo |
| 4. Preparare l'esperimento GPU | Parità PCS ridotta, S1, resti e potenze a blocchi; controlli host e compilazioni statiche CUDA | Collegare CUDA alle dimensioni canoniche, completare contabilità simultanea e condizioni dell'[esperimento della prova](#esperimento-della-prova); ottenere l'autorizzazione per l'esperimento con confronto host/GPU e misure |
| 5. Eseguire la prova completa | Eseguibile CPU esplicito di riferimento; nessun runner GPU ammesso | Solo dopo integrazione e autorizzazione: tre risposte canoniche verificate con stesso W e KV, misurando tutte le risorse; conservare anche gli esiti negativi |

Le implementazioni locali dei punti 1 e 3 possono procedere indipendentemente;
la loro validazione sui pesi reali richiede il punto 2. La calibrazione
non implementa il prover e non chiude gli [obblighi di sicurezza Seed6](security.md#estensione-seed6-e-obblighi-residui).
Un esperimento può misurare il prototipo senza attribuirgli una garanzia
crittografica la cui composizione è ancora aperta.

Il comando `c71_canonical_reference reference-cpu CANDIDATE TABLES PACKED
NEW_JOURNAL_DIRECTORY PREPARATION_BYTES` è un riferimento CPU pesante,
non il comando della campagna H100. Usa il prompt pinned per tre risposte,
crea journal nuovi e non li ripristina o sovrascrive. Input e tabelle hanno
gli stessi formati della calibrazione. `PREPARATION_BYTES` non è un limite
globale di memoria. Non eseguirlo sulla VM; un errore non autorizza retry,
nuovi journal, proroghe o cambio di backend. Anche su un host H100 resta
CPU. La sua disponibilità non chiude i punti 3–4 né l'hard stop provider.
Il report del runner include ora fasi wall e traffico applicativo effettivo
di entrambi i sensi, inclusi Γ/tabelle, installazione e richieste; setup e
distribuzione sono addebitati alla prima risposta. In caso di errore gestito,
stderr conserva `C71_RUN_METRICS`; per timeout/kill restano necessari i log
esterni. Preparazione e inferenza sono ancora fuse e CPU-time, picchi per
ruolo, capacità trattenute e HBM restano da implementare/misurare. Un test
del trasporto con tre corpi sintetici non conta come tre prove canoniche.
Il commitment iniziale ora seleziona coset 2^22 e lo scanner A a 512
ricostruzioni, con parità soltanto ridotta; il vecchio cap iniziale 2^18
non descrive più questo percorso. Restano i workspace query/range e i
kernel densi da adattare. Le prime query A leggono ora finestre originali
fino a 256 MiB e non duplicano la matrice del risultato; la parità è
soltanto ridotta e non chiude la contabilità fisica simultanea.
Singleton, coset S1, OOD e retention sono ora collegati allo scanner
originale con barriere FS separate; il coset extension evita le matrici
complete di conversione. Il
[checkpoint delle riduzioni](../c7.1-history/canonical-residual-scan.md)
è seguito dal [collegamento degli stadi](../c7.1-history/canonical-pcs-stages.md):
geometrie S1/S2/successori e stato fino a D35 sono disponibili nel
riferimento CPU, con P/Q condiviso fra due fold e rilasciato prima dei
commitment. Il supporto delle shape non è un esperimento canonico.
Workspace, CUDA e memoria simultanea rimangono lavoro locale.
Il [gather range](../c7.1-history/canonical-range-gather.md) alimenta ora il
[consumer CPU range A](../c7.1-history/canonical-windowed-range.md), con
canopy/Gram/retention e istogramma raccolto nel primo scan PCS. La parità
è ridotta: nessuna finestra canonica di 2 GiB o prova range D34 è stata
eseguita. Il range W ora riusa il motore CPU sul packed signed originale,
con cut=11/m24 e staging limitato a 256 MiB. Portare entrambi i consumer
su CUDA e completare il conto simultaneo rimane lavoro locale, non una
dipendenza dall'H100.
Nessuna esecuzione W/D35 o A/D34 è acquisita. Il
[checkpoint del collegamento](../c7.1-history/canonical-initial-scan.md)
non ammette il comando CPU come campagna H100 né cambia le autorizzazioni.
I kernel range e l'owner nativo di stream/arena sono compilabili insieme;
ledger, capacità trattenute ed errori asincroni dell'owner hanno controlli
con driver simulato. Il consumer Rust è ora collegato ai callback range
con selezione esplicita della libreria, senza fallback. La parità locale
attraverso l'ABI usa algebra host simulata, non i kernel GPU. Integrazione
del runner complessivo, altri consumer CUDA e contabilità simultanea restano
lavoro locale; la verifica GPU richiede l'esperimento autorizzato.
Questi controlli non abilitano il runner GPU o un pod.
Il kernel denso i16 a quattro MMA INT8 è ora disponibile come componente
compilabile, con modello host di split/frammenti e correzioni. W residente,
owner/fence del flag, batching nel preparatore e misure complete restano
da collegare; il vecchio GEMM CUDA scalare non viene presentato come
questa implementazione o come una misura H100.

Prima di usare credenziali locali eseguire
`scripts/runpod_harness.sh local-secret-preflight`. Un eventuale `.env`
deve essere un file regolare posseduto dall'utente e avere permessi `0600`;
il controllo non lo carica e non stampa nomi o valori. Il `.env` locale
rilevato il 3 ottobre 2026 è stato corretto da `0664` a `0600`.

## Gestione del pod e del repository

Usare [runpod_harness.sh](../../scripts/runpod_harness.sh) per la gestione
di un eventuale pod autorizzato. Il harness permette ispezione e chiusura,
ma non rende affidabile una deadline. Un timer nel container o un processo
locale non è un limite provider e non sblocca l'hard stop. Non sono impliciti
retry, proroghe o una seconda macchina. Prima di compilare o generare
artefatti eseguire `scripts/runpod_harness.sh git-preflight`.

Sincronizzare repository ed evidenze piccole solo tramite Git HTTPS su
`https://github.com/okrame/volta-zk.git`. Le sorgenti pubbliche si leggono
anonimamente. Per pubblicare usare il Secret RunPod `VOLTA_GITHUB_TOKEN`,
con scadenza e permesso Contents read/write limitato al repository.
Non copiare credenziali dalla VM, non usare gh, Git SSH, SCP/rsync o
archivi del repository. Token fuori da URL, configurazioni Git, comandi,
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
Pesi e grandi artefatti restano sul pod; non vengono aggiunti a Git.
La pubblicazione usa un branch unico tramite `git-push runpod/POD_ID/LABEL`.

## Campagna di calibrazione

La proposta è una campagna, una sola candidata Γ, una H100 SXM 80 GB,
massimo 8 ore dalla creazione e 40 USD complessivi. La decisione di avvio
deve fissare SHA pulita, immagine/container con digest, regione, offerta,
costo totale e deadline del provider. La proposta non è avviabile con il
CLI/provider corrente perché tale deadline manca. Nessuna modifica delle
scale o ripartenza è inclusa. Il completamento di tutti i test è l'obiettivo,
non una deroga al limite di tempo.

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
I comandi correnti coprono il punto 2 fino al replay numerico. Per una
campagna che prometta Γ ammesso deve essere già completato il punto 1,
con tempi e risorse del confronto inclusi nel medesimo limite.

### Risorse e costo

| Risorsa | Richiesta proposta / controllo prima del download |
|---|---|
| Compute | 1 H100 SXM 80 GB, almeno 20 vCPU e 125 GB RAM host; verificare l'offerta effettiva |
| Software | Linux x86_64, Python ≥3.11, NumPy, pytest, Rust/Cargo, C/C++ build tools, Git, GNU timeout/time; versioni e immagine registrate |
| Disco | Volume locale 300 GB montato in `/workspace`, container 40 GB; almeno 180 GB liberi prima del download |
| Payload persistente | Shard 62.546.338.248 B + packed 61.394.690.560 B = 123.941.028.808 B |
| Temporanei | Download direttamente in `.partial`, rinomina senza seconda copia; packed e traccia pubblicati atomicamente; nessuna seconda copia BF16/dequantizzata completa |
| Memoria | Ingest nativo richiede 3.355.443.200 B operativi; trial con payload nominato ≤8 GiB; limite AS per processo 64 GiB; osservare anche RSS aggregato/cgroup e cache OS |
| Numerica | Pilot: blocco W i16+f64 ≤27.525.120 B, KV finale f64 1.622.016.000 B; replay KV finale i16 405.504.000 B, più A viva, tabelle, workspace e runtime |
| Traccia privata | Riservare 44 GB per il primo replay: limite conservativo da A nei codec originali, KV finale e framing; il padding è compattato. Resta fuori da Git e rientra nei limiti di disco e tempo |

Questi payload non sono un picco RSS completo. Stop per OOM, swap
sostenuto, RSS aggregato >96 GiB o spazio libero <20 GB; non aumentare
i budget per aggirare un fallimento. Il requisito legacy 256 GiB/400 GB
del pack Python non si applica al `pack --native-packer`: non usare i
subcomandi legacy `preflight`/`report` per ammettere questa macchina.
Il pack nativo verifica già header, entrambi i corpi e output persistito.

Verificare prezzo e disponibilità effettivi al momento dell'autorizzazione.
Il limite proposto è compute ≤3,50 USD/h e costo totale ≤40 USD, inclusi
disco, imposte e altri addebiti. Otto ore di compute possono quindi
costare al più 28 USD; il preventivo dello storage deve rientrare nel
residuo. Nessun network volume, disco lasciato inattivo, secondo pod,
abbonamento o ricarica automatica è incluso nella proposta.

È richiesta **terminazione provider-side a 8 ore**, non soltanto `timeout`
nel container. La [documentazione CLI corrente](https://docs.runpod.io/runpodctl/reference/runpodctl-pod)
non espone una deadline e la release v2.12.0 ha rimosso i vecchi flag perché
inefficaci. In assenza di un nuovo controllo provider leggibile e provato,
STOP: non installare una vecchia CLI e non sostituire il requisito con un
timer locale. Ricontrollare la documentazione e la
[procedura di gestione](#gestione-del-pod-e-del-repository) all'autorizzazione.

La terminazione distrugge il volume locale: pubblicare prima i piccoli
artefatti, log e digest, e conservare eventuali dati privati solo su una
destinazione separatamente autorizzata. Shard, packed, dump privati e
tabelle grandi non vanno in Git. Il bundle Γ piccolo e le ricette
consentono la ricostruzione; non promettono persistenza del packed.
Non usare `pause` come chiusura economica: il volume continuerebbe a
costare, come documentato nelle [opzioni storage](https://docs.runpod.io/pods/storage/types).

### Tempi massimi da richiudere prima dell'autorizzazione

| Fase seriale | Massimo |
|---|---:|
| Ambiente, build, controlli piccoli | 45 min |
| Acquisizione dei due shard e hash durante il download | 30 min totali |
| Ingest nativo, nuovo hash dei corpi e packed persistito | 30 min |
| Pilot floating sui tre contesti e compilazione candidata | 90 min |
| Primo replay, traccia e confronto indipendente da KV vuoto | **Da misurare**; il precedente limite di 120 min copriva solo il replay |
| Secondo replay da KV vuoto, stessa candidata | 90 min |
| Ledger, conto delle risorse, bundle e pubblicazione | 45 min |
| Riserva per trasferimento log/stop | 30 min |

Il totale massimo di 8 h non è attualmente dimostrato perché il nuovo
confronto è seriale al primo replay. Prima dell'autorizzazione fissare
`TRACE_STEP_SECONDS` e `NATIVE_TRACE_TIMEOUT_SECONDS` con una misura o un
preventivo conservativo e riallocare le altre fasi senza superare 8 h; in
assenza, STOP. Le deadline interne
del pilot/replay non coprono tutti gli hash e la generazione tabelle:
il timeout esterno copre l'intero comando. Nessuna fase parte se non ha
il proprio budget residuo più almeno 30 minuti per conservare l'evidenza.
Questi massimi non garantiscono il completamento: anche comandi accessori
e passaggi manuali consumano la stessa finestra. Al primo errore si saltano
le fasi successive e si pubblica il fallimento.

### Identità degli input

Usare esclusivamente [checkpoint, shard, digest e workload delle specifiche](specs.md#input-e-identità),
mai `main`. I comandi importano le stesse costanti da
[c7_d126_gemma_weight_ingest.py](../../scripts/c7_d126_gemma_weight_ingest.py).
Nessun dataset nuovo, imposizione dei token prodotti dal pilot floating
o certificazione di qualità generale. Accesso HF/licenza deve essere già
valido; un 401/403 ferma la fase, senza accettare licenze o cambiare checkpoint.

### Comandi dopo autorizzazione esplicita e risoluzione dell'hard stop

Gli snippet seguenti **non sono stati eseguiti sui pesi reali**. Prima
dell'autorizzazione fissare offerta/regione, digest immagine con toolchain,
SHA pulita, `POD_CREATED_EPOCH`, `TRACE_STEP_SECONDS`,
`NATIVE_TRACE_TIMEOUT_SECONDS` e la riallocazione completa entro 8 ore.
Verificare i flag con la CLI realmente installata prima
della creazione; mappare i Secret nel template, mai nei comandi/log.
Non esiste oggi un comando di creazione ammesso da questo runbook.

```bash
runpodctl version
runpodctl pod create --help
# STOP: approvare un comando solo quando espone una deadline provider
# verificabile; il CLI corrente non la offre.
```

Il GPU ID va confrontato con `runpodctl gpu list`: se l'ID differisce,
selezionare l'ID SXM effettivo senza cambiare classe, prezzo o risorse.
Nessuna chiamata al provider è necessaria per preparare questo documento.
Checkout anonimo HTTPS, poi credenziale Git solo tramite Secret
`VOLTA_GITHUB_TOKEN`, scoped al repository ed expiring; eventuale
`HF_TOKEN` è un Secret separato con sola lettura, non copiato dalla VM.

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
export CAMPAIGN_END_EPOCH=$((POD_CREATED_EPOCH + 8 * 3600 - 1800))
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
un file vuoto/troncato come risultato. La deadline provider prevale sul
controller locale. Preparare venv/toolchain nella fase ambiente, senza
upgrade non registrati; `pip freeze`, `rustc -Vv`, `cargo -V`, `uname -a`,
quote/deadline, CPU/RAM/disco e SHA immagine vanno nei log.

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
e un worker; non sostituiscono i trial reali. Non eseguire workspace E2E.

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
stop; una revisione delle scale comporta nuova candidata, nuova autorizzazione e
ripartenza da O=0, mai riparazione del solo contesto fallito.

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
La futura ricevuta di congelamento deve referenziare il report di confronto,
la copertura esatta e ogni assunzione residua; in sua assenza resta aperta.
La prima autorizzazione può fermarsi al bundle numerico; non acquistare
tempo GPU per «completare automaticamente il congelamento» con un tool assente.

Conservare in una nuova directory immutabile, senza aggiornare i manifest
storici: candidata, descrizione ID, report ingest/pilot, ricette e digest
tabelle, entrambi i report interi, eventuali golden/audit, conto delle risorse,
toolchain/image/SHA, quote/deadline, comandi, stdout/stderr, exit, tempi,
RSS e ricevuta di costo. Il manifest nuovo elenca path relativi, byte e
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

Verificare da un checkout remoto separato il commit e i file pubblicati,
e l'eventuale destinazione autorizzata dei dati da conservare. Solo dopo
eseguire il `delete` della [gestione pod](#gestione-del-pod-e-del-repository).
Quando l'hard stop sarà risolto, la terminazione provider dovrà avvenire
comunque alla deadline; non rinviarla per salvare un run incompleto. Dopo
l'ammissione di Γ, portare il profilo
e il conto delle risorse alla [preparazione dell'esperimento della prova](#esperimento-della-prova), che richiede ancora lavoro
completo, picco con margine, lower congiunto e harness della prova. Questa
campagna non misura prova/PCG, non emette certificati e non autorizza il
benchmark della prova H100.

## Esperimento della prova

Questa fase non ha ancora un comando canonico completo pronto all'uso.
L'esempio `c71_matrix` è un diagnostico e `c71_calibration` esegue il
replay numerico: nessuno dei due è il benchmark della prova Gemma.
Prima di proporre una spesa per la prova chiudere i seguenti requisiti:

1. Audit della provenienza dei fork completato nel
   [record pulito](../../benchmarks/results/c71-fork-provenance-2026-10-02-4fbfbfb8afd0.json);
   Γ reale validato e congelato, con confronto indipendente documentato;
   ricette, tabelle, layout e riserve ricompilati a O=0/150/300.
2. Costruzione integrata corretta su input ridotti: preparatore, getter,
   W installata, lookup/GKR/range/PCS, pool reale, framing e promozione
   sullo stesso registro. I test componenti non sostituiscono questa verifica.
3. Conto completo del lavoro, memoria allocata e riservata simultanea,
   trasferimenti, PCG, replay, hash, FFT, proof e allocator. Almeno
   256 MiB liberi nell'arena e 1 GiB globale; nessuno spill dinamico.
4. Limite inferiore congiunto compatibile con 65 s in tutti i contesti.
   Non serve conoscere in anticipo un limite superiore del tempo H100.
   I valori parziali in specs non chiudono questo requisito.
5. Harness e input del minimo esperimento, SHA pulita, fingerprint
   hardware/toolchain, durata massima, costo e soglie di accettazione
   o arresto verificabili, quindi autorizzazione di quella campagna.

Gli esperimenti GPU devono confrontare prima i risultati con il riferimento
host/nativo: FFT diretta/inversa, resti e P/Q nella base corretta, hash salato,
range e operatori numerici. Poi si misurano le fasi rappresentative con i
loro stati simultaneamente vivi. Un kernel veloce da solo non dimostra
il tempo completo. CUDA richiesto ma non disponibile deve produrre errore,
senza un percorso CPU sostitutivo. La produzione usa PCG reale/AES.

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
eseguito deve essere pulita. I record non autorizzano nuovi tentativi;
aggiornare i cinque documenti correnti solo quando cambia un fatto,
collegando la nuova evidenza senza sovrascrivere quella precedente.
