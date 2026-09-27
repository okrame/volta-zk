> Documento storico: descrive il proprio checkpoint, non le istruzioni correnti.
> Per implementare usare il [design corrente](../c7.1/design.md); per la provenienza vedere la [mappa](README.md).

# C7.1 — tranche separata di calibrazione Γ

Piano del **2026-09-27**, richiesto dal proprietario. **Non autorizzato
all'esecuzione:** nessun download dei pesi, pod, GPU o spesa è stato avviato.
La preparazione di questo piano chiude il goal locale secondo lo steering
del 2026-09-27; non significa «pronto per il benchmark della prova».
Il [preflight della prova](preflight.md) resta NO-GO e distinto.

## Richiesta di autorizzazione proposta

Autorizzare eventualmente **una sola campagna**, una sola candidata Γ,
su un pod H100 SXM 80 GB, fino a **8 ore dalla creazione**, tetto assoluto
proposto **40 USD inclusi storage, eventuali imposte e altri addebiti**. Nessuna
ripartenza, proroga, cambio delle scale o seconda macchina impliciti.
Il GO deve riportare SHA pulita, immagine/container digest, regione,
offerta effettiva, deadline del provider e approvazione di questi limiti.
Il presente documento non è quel GO.

**Limite tecnico importante:** i comandi disponibili eseguono NumPy/BLAS
CPU per il pilot e Rust CPU per il replay intero. Non esiste qui un backend
CUDA completo di calibrazione; `nvidia-smi` non lo attiva. Il pod H100 è
una destinazione operativa richiesta, non una promessa di accelerazione.
Un host CPU equivalente è l'alternativa meno costosa, da selezionare
esplicitamente prima del GO. Non sostituire il replay con Transformers,
BF16, TF32 o inferenza floating: non verificano la relazione intera C7.1.

Il proprietario ha ristretto il limite a 8 ore, indicando come obiettivo
ideale il completamento di tutti i test E2E. Si dà priorità alla catena
completa di calibrazione sui tre contesti, poi alla ripetibilità e agli
audit; non si sostituisce un E2E incompleto con test di soli componenti.
Gli E2E della prova canonica richiedono ancora i relativi adapter e gate:
non sono resi disponibili né autorizzati da questo desiderio di copertura.
Nessuna proroga delle 8 ore è implicita per finire i test.

Il completamento entro 8 ore **non è misurato né garantito**. Il pilot
conta 13.390.420.377.600 prodotti di matrice e 26.782.043.904.000 B di
letture W logiche; non sono traffico fisico né un tempo H100. Il replay
scalare può esaurire la deadline. L'esito ammesso in quel caso è un record
di fallimento e stop, non Γ calibrato né un rinnovo automatico.

### Macchina, spazio e costo

| Risorsa | Richiesta proposta / controllo prima del download |
|---|---|
| Compute | 1 H100 SXM 80 GB, almeno 20 vCPU e 125 GB RAM host; verificare l'offerta effettiva |
| Software | Linux x86_64, Python ≥3.11, NumPy, pytest, Rust/Cargo, C/C++ build tools, Git, GNU timeout/time; versioni e immagine registrate |
| Disco | Volume locale 300 GB montato in `/workspace`, container 40 GB; almeno 180 GB liberi prima del download |
| Payload persistente | Shard 62.546.338.248 B + packed 61.394.690.560 B = 123.941.028.808 B |
| Temporanei | Download direttamente in `.partial`, rinomina senza seconda copia; packed pubblicato atomicamente; nessuna seconda copia BF16/dequantizzata completa |
| Memoria | Ingest nativo richiede 3.355.443.200 B operativi; trial con payload nominato ≤8 GiB; limite AS per processo 64 GiB; osservare anche RSS aggregato/cgroup e cache OS |
| Numerica | Pilot: blocco W i16+f64 ≤27.525.120 B, KV finale f64 1.622.016.000 B; replay KV finale i16 405.504.000 B, più A viva, tabelle, workspace e runtime |

Questi payload non sono un picco RSS completo. Stop per OOM, swap
sostenuto, RSS aggregato >96 GiB o spazio libero <20 GB; non aumentare
i budget per aggirare un fallimento. Il requisito legacy 256 GiB/400 GB
del pack Python non si applica al `pack --native-packer`: non usare i
subcomandi legacy `preflight`/`report` per ammettere questa macchina.
Il pack nativo verifica già header, entrambi i corpi e output persistito.

Il [listino RunPod](https://www.runpod.io/pricing), consultato il
2026-09-27, mostra H100 SXM a 3,49 USD/h, 125 GB RAM e 20 vCPU; storage
container/volume running a 0,10 USD/GB/mese. Sono riferimenti pubblici,
non un'offerta prenotata. Imporre compute ≤3,50 USD/h: 8 ore costano
al più 28 USD, più circa 0,38 USD per 340 GB per 8 ore (mese di 720 ore).
Il totale preventivato con imposte/extra deve comunque essere ≤40 USD;
in caso contrario non creare il pod. Nessun network volume, disco idle,
secondo pod, abbonamento o ricarica automatica incluso nella proposta.

Usare **terminazione provider-side a 8 ore**, non soltanto `timeout`
nel container. Verificare che la versione installata di `runpodctl`
supporti `--terminate-after` e che la deadline sia realmente registrata;
se manca, STOP, non sostituire con un timer locale. La
[documentazione CLI](https://docs.runpod.io/runpodctl/reference/runpodctl-pod)
e la [procedura del repository](runpod.md) vanno ricontrollate al GO.

La terminazione distrugge il volume locale: pubblicare prima i piccoli
artefatti, log e digest, e conservare eventuali dati privati solo su una
destinazione separatamente autorizzata. Shard, packed, dump privati e
tabelle grandi non vanno in Git. Il bundle Γ piccolo e le ricette
consentono la ricostruzione; non promettono persistenza del packed.
Non usare `pause` come chiusura economica: il volume continuerebbe a
costare, come documentato nelle [opzioni storage](https://docs.runpod.io/pods/storage/types).

### Tempi massimi, non stime di completamento

| Fase seriale | Massimo |
|---|---:|
| Ambiente, build, controlli piccoli | 45 min |
| Acquisizione dei due shard e hash durante il download | 30 min totali |
| Ingest nativo, nuovo hash dei corpi e packed persistito | 30 min |
| Pilot floating sui tre contesti e compilazione candidata | 90 min |
| Replay intero completo da KV vuoto | 120 min |
| Secondo replay da KV vuoto, stessa candidata | 90 min |
| Tabelle, confronto, ledger, bundle e pubblicazione | 45 min |
| Riserva per trasferimento log/stop | 30 min |

Totale massimo 8 h, incluse preparazione e download. Le deadline interne
del pilot/replay non coprono tutti gli hash e la generazione tabelle:
il timeout esterno copre l'intero comando. Nessuna fase parte se non ha
il proprio budget residuo più almeno 30 minuti per conservare l'evidenza.
Al primo errore si saltano le fasi successive e si pubblica il fallimento.

## Identità degli input

Modello `google/gemma-4-31B`, revisione immutabile
`5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89`, non `main`.
I [metadati pinned](../../manifests/c7-d126-gemma31b-source-metadata-v1.json)
e il [manifest dei terminali](../../manifests/c7-d126-gemma31b-terminals-v1.csv)
definiscono header, offset, 772 tensori privati e scalari pubblici.

| File | Byte | SHA-256 completo |
|---|---:|---|
| `model-00001-of-00002.safetensors` | 49.784.788.364 | `186fa361e76abbb5f48ffb3d9965181a5da33522e39c25eb75d7241da1637aac` |
| `model-00002-of-00002.safetensors` | 12.761.549.884 | `b78ae8294981a6d674c47f2261d34240b7539bbeafb4f7d0525f6167946e6da0` |

Workload: [manifest originale](../../manifests/c7-d126-gemma31b-workload-v1.json),
SHA-256 `70875c659be2b2bc0079a954233da639fe1584136c17f8fb353b589454a5d62b`.
Tre tentativi ordinati O=0/150/300: ogni volta 100 token prompt pinned,
50 token generati dalla relazione intera; KV anche dell'ultimo token.
Unica mappa 772 W + 1.435 A, embedding/head coerente, e_Pi=-14.
Nessun dataset nuovo, teacher forcing dei token floating o certificazione
di qualità generale. Accesso HF/licenza deve essere già valido; un
401/403 ferma la fase, senza accettare licenze o cambiare checkpoint.

## Comandi dopo un GO esplicito

Gli snippet seguenti **non sono stati eseguiti sui pesi reali**. I soli
parametri da fissare al GO sono offerta/regione, digest immagine con
toolchain disponibile, SHA pulita del piano e `POD_CREATED_EPOCH` ricavato
dal provider. Verificare i flag con la CLI realmente installata prima
della creazione; mappare i Secret nel template, mai nei comandi/log.

```bash
runpodctl pod create --image "$APPROVED_IMAGE_DIGEST" \
  --name c71-gamma-one-candidate --gpu-id "NVIDIA H100 80GB HBM3" \
  --gpu-count 1 --cloud-type SECURE --data-center-ids "$APPROVED_REGION" \
  --container-disk-in-gb 40 --volume-in-gb 300 \
  --volume-mount-path /workspace --terminate-after 8h
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
run_step 300 venv python3 -m venv .venv
run_step 300 dependencies .venv/bin/python -m pip install numpy==2.5.1 pytest==9.1.1
run_step 1800 build bash -c '
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
run_step 60 calibration-checks .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_c71_calibration.py
run_step 60 pilot-checks .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_c71_activation_pilot.py
run_step 60 ingest-checks .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_c7_d126_gemma_native_bf16.py tests/test_c7_d126_gemma_weight_ingest.py
```

La venv e le versioni dei pacchetti devono essere predisposte nella fase
ambiente; i comandi assumono `.venv/bin/python` con NumPy e pytest già
verificati. Non copiare la venv locale o credenziali al pod. Una build
priva delle dipendenze native non autorizza un altro pod:
fermare nella fase ambiente. I controlli piccoli mantengono 60 s e un
worker; non sostituiscono i trial reali. Non eseguire workspace E2E.

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
run_step 7200 integer-1 .venv/bin/python scripts/c71_calibrate.py run \
  --native "$NATIVE" --candidate "$CANDIDATE" --ingest-report "$INGEST" \
  --packed "$PACKED" --output "$RUN/integer-1.json" \
  --payload-bytes 8589934592 --timeout-seconds 6900
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
indipendente. I 150 token floating non sono il golden intero. Una
candidata che non compila o produce overflow/range failure richiede
stop; una revisione delle scale comporta nuova candidata, nuovo GO e
ripartenza da O=0, mai riparazione del solo contesto fallito.

## Successo, freeze e limiti del verificatore disponibile

Prima di congelare verificare, sui file persistiti e non sul solo exit 0:

1. Identità shard/packed/ingest/workload/native e SHA pulita invarianti;
   `pilot/report.json` completo, `success:true`, `candidate_compiles:true`.
2. Stessa mappa W/A completa e stesse ricette nei tre contesti; tabelle
   certificate rigenerate con Python, 24.414.870 B, SHA-256 identico fra
   `tables`, entrambi i replay e ledger, più digest nativo coerente.
3. Entrambi i report con `complete_integer_trial:true`, `exit_code:0`,
   `native_exit_code:0`, `packed_hash_checked:true`,
   `tables_generated_by_certified_reference:true`. Tre `responses`,
   O=0/150/300, 150 token ciascuna, prefisso esatto dei 100 token pinned,
   50 output validi; extents/copertura di ogni ID A e contatori completi.
4. `responses` identiche fra i due replay, inclusi token, extents e lavoro;
   nessun overflow, non-finito, saturazione, marker di errore o trial
   parziale. Il controller deve avere assorbito l'ultimo token in KV;
   non inferirlo dalla sola lunghezza della lista dei token.
5. RNE/BF16, RMS/RNE numerici, LUT e routing hanno controlli della stessa
   relazione intera Python/Rust, non uguaglianza col pilot floating.
   **L'export di golden reali intermedi e un audit Python/Rust completo
   del run non sono implementati dal CLI attuale.** Min/max e una seconda
   esecuzione dello stesso Rust non li sostituiscono. Per il freeze con
   quel confronto completo manca un adapter di export/audit da sviluppare
   e verificare separatamente: fermarsi a `candidate_integer_validated`,
   non inventare un comando `freeze` né un report di bit-equality.

Il piano conserva quindi due esiti distinti: bundle numerico riproducibile
ottenibile con i comandi correnti, e **Γ ammesso/congelato** soltanto dopo
il controllo indipendente richiesto dal [preflight](preflight.md#real-calibrated-gamma).
Non si cambia un `calibrated:false` prodotto dai tool in `true` a mano.
La futura ricevuta di freeze deve referenziare il report di confronto,
la copertura esatta e ogni assunzione residua; in sua assenza resta aperta.
È un limite esplicito del handoff, non un'autorizzazione ad allentare il gate.
La prima autorizzazione può fermarsi al bundle numerico; non acquistare
tempo GPU per «completare automaticamente il freeze» con un tool assente.
L'implementazione dell'export/audit è lavoro locale indipendente da
eseguire prima di una campagna che prometta Γ definitivamente ammesso.

Conservare in una nuova directory immutabile, senza aggiornare i manifest
storici: candidata, descrizione ID, report ingest/pilot, ricette e digest
tabelle, entrambi i report interi, eventuali golden/audit, ledger,
toolchain/image/SHA, quote/deadline, comandi, stdout/stderr, exit, tempi,
RSS e ricevuta di costo. Il manifest nuovo elenca path relativi, byte e
SHA-256 di ciascun file; hash anche del manifest, scrittura esclusiva e
lettura di verifica. Le tabelle possono essere rigenerate dai digest e
ricette; i dump privati richiedono storage autorizzato e non entrano in Git.

```bash
find "$RUN" -path "$RUN/weights" -prune -o -type f -print0 \
  | sort -z | xargs -0 sha256sum > /workspace/c71-gamma-files.sha256.partial
test ! -e "$RUN/files.sha256"
ln /workspace/c71-gamma-files.sha256.partial "$RUN/files.sha256"
rm /workspace/c71-gamma-files.sha256.partial
sha256sum --check "$RUN/files.sha256"
```

La lista viene scritta fuori da RUN e pubblicata senza overwrite:
nessun digest di lista autoreferenziale è ammesso. Il bundle in Git usa
solo la selezione piccola revisionata, non `git add "$RUN"`. Un record
nuovo va in `benchmarks/results/c71-calibration-DATE-GITSHA.json`, con
`git_dirty:false` riferito al codice eseguito, esito e digest degli output.
Pubblicarlo secondo la procedura RunPod in un branch unico:

```bash
scripts/runpod_harness.sh git-push "runpod/$RUNPOD_POD_ID/c71-gamma"
scripts/runpod_harness.sh delete "$RUNPOD_POD_ID" --confirm "$RUNPOD_POD_ID"
```

Prima del delete verificare dal remote il commit delle evidenze e
l'eventuale destinazione autorizzata dei dati da conservare. Alla deadline
la terminazione provider avviene comunque; non rinviarla per salvare un
run incompleto. Al successo numerico, Γ e ledger vanno riportati al
[preflight della prova](preflight.md), che richiede ancora lavoro
completo, picco con margine, lower congiunto e harness della prova. Questa
campagna non misura prova/PCG, non emette certificati e non autorizza il
benchmark della prova H100.
