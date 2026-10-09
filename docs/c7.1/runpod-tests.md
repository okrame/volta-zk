# C7.1 — test su RunPod

[Design](design.md) · [Specifiche](specs.md) · [Sicurezza](security.md) ·
[Test locali](local-tests.md) · [Archivio](../c7.1-history/README.md)

## Stato e sequenza operativa

Γ è **ammesso** per le identità pinned dal
[record del 7 ottobre](../../benchmarks/results/c71-gamma-admission-2026-10-07-868a3e8.json):
due replay interi identici, confronto indipendente completo, 450 token,
3.471 sorgenti A per contesto e 120 sorgenti KV finali da 450 righe.
La [diagnostica della prova](../../benchmarks/results/c71-cuda-experiment-2026-10-07-868a3e8.json)
è **INCOMPLETA**, exit 124 dopo 2.461,09 s nel commitment W, prima delle
risposte. Nessun certificato canonico o tempo completo della prova è acquisito.
Il runner `experiment-cuda` è misto: inferenza/replay/range e commitment
iniziali W/A GPU; sali/PCS successive/GKR non-range/Seed6/verifica CPU. Le [risorse misurate e le priorità](design.md#risultati-attuali-e-prossime-ottimizzazioni)
sono riassunte nel design. La campagna precedente è chiusa e il pod è spento.

Il goal locale dell'8 ottobre prepara l'intero percorso crittografico e
si conclude prima della campagna H100. Hardware e durata richiedono nuova
autorizzazione. I controlli telemetria/XOF sono in
[local-tests](local-tests.md#controlli-nativi-della-costruzione-corrente);
la prima integrazione conserva la geometria W/A corrente.

Il [primo checkpoint locale](../../benchmarks/results/c71-crypto-preparation-local-2026-10-08-04ab8ed1c4ce.json)
ha telemetria/XOF integrati e parità ridotte positive. Il lavoro locale
successivo ha integrato W/A residenti; prosegue con i confronti esatti,
mentre il goal è ancora
attivo e non autorizza riattivazione, nuovi pod o una campagna.

Il [passo hash W](../c7.1-history/crypto-w-hash-2026-10-08.md) prepara
foglie incrementali e Merkle GPU nello stesso owner, con sali a finestre.
Il runner CUDA seleziona ora la catena nel Tree W, con lifecycle/aperture
integrati e parità locale. Il frontier strided è verificato come
componente condiviso, senza esecuzione CUDA. Nella campagna autorizzata compilare anche
`cuda/c71_pcs_hash.cu`; librerie antecedenti prive dei simboli PCS sono
rifiutate. La parità host non è esecuzione CUDA o misura H100.
Il [checkpoint pulito W hash](../../benchmarks/results/c71-crypto-w-hash-local-2026-10-08-0bf5814bf9c4.json)
conserva root naturali/strided, sali e arresti verificati localmente.
Il [passo accumuli/FFT](../c7.1-history/crypto-w-scan-fft-2026-10-08.md)
prepara e verifica la catena W→accumuli→FFT→hash/Merkle nelle fixture:
128 colonne/32 coset, pad originali e rifiuti terminali. Il
passo [Tree W](../c7.1-history/crypto-w-tree-2026-10-08.md) integra la
catena nel runner CUDA; il passo A successivo è descritto sotto.
Nella futura build aggiungere anche `cuda/c71_pcs_weight.cu`; le FFT
riusano `cuda/c71_fft.cuh`. Restano da verificare compilazione sm_90,
parità hardware, picchi fisici e tempi. Nessun riavvio hardware finché
il goal locale non è pronto e hardware/durata nuovamente autorizzati.
Il [record locale pulito](../../benchmarks/results/c71-crypto-w-scan-fft-local-2026-10-08-e66e0fbd45db.json)
verifica componenti e arresti con driver simulato; non compila CUDA,
non misura H100. W CUDA seleziona 128 scansioni (analitiche sul pinned),
il riferimento CPU resta a 1.024 e A resta a 512 ricostruzioni. La parità
composta completa usa soltanto nel test una tabella di righe di riferimento
da 16 MiB; il test distinto Tree confronta il getter effettivo. Il D15
non cached supera ancora 60 s locali ed è un obbligo prestazionale aperto.
Il conto W corregge con nuova evidenza il secondo flag simultaneo (+256 B);
non modifica i record precedenti e non concede credito di picco completo.
Il [record pulito Tree](../../benchmarks/results/c71-crypto-w-tree-local-2026-10-08-6b3535856cc5.json)
conserva la selezione del runner e tutta la provenienza locale; dodici
test Rust e nove Python positivi. Il [receipt](../c7.1-history/crypto-w-tree-evidence-2026-10-08.md)
delimita le fixture e i fallimenti. Il Tree A è ora integrato sotto; confronto Tensor Core e costi
residui di sampler/aperture/prova restano lavoro del goal locale.

Il [componente A residente](../c7.1-history/crypto-a-source-2026-10-08.md)
prepara scanner, accumuli su quattro coset/tutte le colonne, istogramma
fuso, pad/FFT e foglie complete senza download di righe. Tre geometrie
e 28 arresti sono verificati con driver host; il passo successivo lo
seleziona nel Tree/runner A senza modificare le 512 ricostruzioni.
La nuova build completa deve includere anche `cuda/c71_pcs_source.cu`:
assenza dei cinque nuovi simboli è terminale, anche per un owner W.
L'owner host cresce di 88 B; lo screen candidato A lascia 326.710.016 B
per gli altri owner host, prima della verifica del budget simultaneo
integrato e del picco fisico. Nessun credito H100 o autorizzazione di
hardware/durata segue da questi controlli.
Il [record pulito A](../../benchmarks/results/c71-crypto-a-source-local-2026-10-08-98ac67808e29.json)
e il [receipt](../c7.1-history/crypto-a-source-evidence-2026-10-08.md)
conservano provenienza, regressioni W e limiti del componente.

Il [Tree A](../c7.1-history/crypto-a-tree-2026-10-08.md) è selezionato nel runner CUDA e il
[record pulito](../../benchmarks/results/c71-crypto-a-tree-local-2026-10-08-2603bbb04013.json) ha 18 test Rust/12 Python positivi. Prova
composta W/A con cache iniziale solo nella fixture, getter effettivi
verificati separatamente e timeout uncached A conservato. Sali strided
batched e un fence duplicato sono ottimizzati con parità locale. La
candidata limb16 è emulata contro i128 e ora collegata al confronto
sullo stesso owner, senza selezione nel runner. La futura libreria deve
includere anche `cuda/c71_pcs_weight_tensor.cu`: i due nuovi simboli ABI4
sono obbligatori. Il [checkpoint del 9 ottobre](../c7.1-history/crypto-components-2026-10-09.md)
ha closure lineare a una scan per round, componente GPU XOF esatta e
candidata QK/PV corretta per causalità per-riga, tutte verificate in host.
Restano integrazione owner/Tree GPU XOF, query/S1/closure GPU, profilo
GKR/range e selezione QK/PV secondo misura, conto simultaneo completo.
Il goal resta attivo: non riattivare pod
o hardware. Γ resta riutilizzabile dopo i controlli normali di identità;
la campagna futura misurerà separatamente installazione, setup,
inferenza, prova e verifica, dopo nuova autorizzazione di hardware/durata.

Il [diagnostico W](../../cuda/c71_pcs_weight_compare.cpp) è pronto per
la futura campagna: compilare e linkare contro la libreria CUDA reale,
confrontare tutte le word canoniche postFFT e tutti i digest con oracle
indipendente, una warmup e tre rep in ordine alternato per gruppo.
La W sintetica da4MiB, R64/Q256, è un componente che entra in L2 e ha pochi
CTA: i suoi tempi non sostituiscono il benchmark W pinned. Il diagnostico
rifiuta il driver test. Non lanciarlo prima della nuova autorizzazione.
Le candidate sali e attention richiedono anche compilazione sm_90 e
controlli reali di seek/cap, basi, pad, root e letture causali prima
della selezione; il default ordinario/scalare rimane il confronto.

Percorso principale: preparazione locale → autorizzazione della nuova
campagna → verifica dell'ambiente e riuso di Γ → parità e misure delle
fasi ottimizzate → esperimento O=0/150/300 → conservazione e arresto.
La [calibrazione](#campagna-di-calibrazione) è un ramo condizionale,
necessario quando l'ammissione pertinente viene invalidata. Le misure
ridotte indipendenti possono precederla; la prova completa richiede Γ ammesso.
Cronache, pod, deadline, proroghe e stime superate sono nel
[runbook storico](../c7.1-history/runpod-tests-2026-10-07.md).

## Autorizzazione e limiti

Regole permanenti approvate dal proprietario l'8 ottobre 2026;
[motivazione e decisioni](../c7.1-history/operating-rules-2026-10-08.md).
Questo documento non avvia una campagna a pagamento. L'istruzione corrente
fissa hardware, ambito, durata propria della campagna e riserva di chiusura.
L'agent registra deadline e responsabile dello spegnimento dall'avvio
provider, verifica l'accesso all'arresto API e predispone un guard indipendente.
Non spostare l'inizio al primo SSH. Non serve un preventivo economico.
Su un pod già autorizzato verificare i limiti senza chiedere nuova conferma.
Le durate storiche, incluse le sei ore, non sono default della nuova campagna.

Una campagna autorizzata comprende correzioni, microbenchmark e nuovi trial
entro gli stessi hardware, ambito e termine. Dopo un fallimento, chiudere
il run, conservarne l'esito, risolverne i prerequisiti e usare file/journal
nuovi, KV iniziale vuoto e correlazioni fresche. Non riprendere lo stato
terminale. Ulteriore durata, altro hardware, diverso ambito o trust model
richiedono una nuova decisione; nessuna conferma per ogni trial già coperto.

| Ambiente | Limite e controllo |
|---|---|
| Controlli locali | 60 s / 2 GiB AS per invocazione, un worker; compilazione mirata secondo [local-tests](local-tests.md#limiti-e-ambiente) |
| Processi CPU RunPod | AS 64 GiB; monitorare anche RSS aggregato, cgroup, swap e disco |
| Processi CUDA RunPod | Nessun cap AS; monitoraggio e arresto al superamento dei limiti fisici, dell'arena o della deadline |
| Prova canonica | Arena comune e margini del [contratto](design.md#contratto-delle-risorse), con conto simultaneo host/device |
| Calibrazione offline | Limiti fisici della sezione [risorse](#risorse), distinti dall'arena della prova |

L'assenza del cap virtuale CUDA non rimuove alcun limite fisico. Per wrapper
CPU che generano figli CUDA impostare solo il soft cap CPU a 64 GiB, con
hard AS illimitato: il wrapper rimuove il soft cap soltanto nel figlio CUDA.
Il confronto indipendente resta CPU sotto 64 GiB. Controllare `ulimit -H -v`
prima del lancio; se è già limitato, predisporre una nuova shell dal launcher
corretto. Le eccezioni AS non richiedono una nuova approvazione per campagna.

Monitorare l'albero processi, HBM, cgroup/swap e disco; i campioni non sono
un picco completo. [c71_campaign_measure.py](../../scripts/c71_campaign_measure.py)
richiede `AUTHORIZED_END_EPOCH` e UUID in `CUDA_VISIBLE_DEVICES`; il suo
arresto deve raggiungere i gruppi figli. Il timeout di un processo non spegne
il pod. Verificare lo stato finale dal provider entro la deadline, anche
se il salvataggio è incompleto. I vecchi flag provider di deadline non
sono un meccanismo affidabile di arresto.

Codice ed evidenze piccole pubblicabili sono **preautorizzati al push Git
HTTPS su un branch dedicato** al task/campagna, senza conferme per commit.
Revisionare il contenuto prima del push; niente segreti, pesi, A/KV o dump
privati. Niente force-push o merge implicito. Questa autorizzazione alla
pubblicazione non autorizza nuovo hardware o durata.

## Conservazione e pulizia degli artefatti

La destinazione persistente è `/home/okrame/projects/volta-zk/artifact/c7.1-pod/`,
con tetto complessivo **10.000.000.000 B**, non per campagna. Prima di nuovi
export inventariare i file e rimuovere copie obsolete/ridondanti non più
necessarie. Conservare input per il riuso di Γ, ricette/tabelle, ricevute,
report, manifest/hash, provenienza e testimonianze uniche dei fallimenti.
Shard, packed e tracce grandi restano fuori dal bundle e da Git.

La pulizia è autorizzata per copie del codice già verificate in Git,
binari intermedi superati e ricostruibili, cache e duplicati verificati.
Un bundle vecchio può contenere materiale ancora necessario: controllare
le dipendenze prima di cancellare. Per ogni rimozione registrare prima
path, byte, hash, motivo e sostituto/provenienza in una nuova ricevuta di
ritenzione; verificare il sostituto prima dell'unlink. Lasciare invariati
manifest storici e record benchmark: il manifest resta la fotografia
originale, la ricevuta distingue esplicitamente file ritirati da corruzioni.
Il controllo di riuso deve verificare tutti i file necessari ancora presenti;
un file necessario mancante blocca quel riuso finché ripristinato e verificato.
Non cancellare evidenza unica o input di Γ soltanto perché datati.
La [pulizia dell'8 ottobre](../c7.1-history/artifact-retention-2026-10-08.md)
ha recuperato 88.395.165 B; la ricevuta è
`retention-20261008T080649Z/`, necessaria per verificare i bundle storici.

## Riuso del bundle

Per riusare il bundle in una nuova campagna, verificarne manifest, hash
ed eventuali ricevute di ritenzione dalla destinazione persistente e confrontare modello/packed, workload,
Γ, tabelle e ricette con le identità validate. Registrare il record di
provenienza: si possono saltare le fasi numeriche già validate se codice
e ambiente pertinenti sono invariati, oppure dopo una verifica documentata
dell'impatto delle differenze. Un bundle parziale conserva solo il credito
delle fasi completate. Trasferire solo ciò che
serve: report/scale per controllare la rigenerazione e binari se compatibili
con CPU/ISA, ABI CUDA, librerie e codice numerico pertinente. Altrimenti
ricompilare; un binario riutilizzato mantiene la SHA originale di build.
Hash e ricette non conservano da soli il packed. Sui nuovi file verificare
nuovamente corpi shard e hash packed/esponenti; sullo stesso pod verificare
i file esistenti prima di saltare download/ingest.
Cambiare modello, byte W, workload, semantica, scale, tabelle o ricette
invalida l'ammissione pertinente. Cambiamenti numerici o d'ambiente
richiedono verifica documentata dell'impatto; sole note o percorsi dei
file non cambiano gli input numerici.
Sulla nuova H100 verificare ambiente e parità; picchi fisici e tempi
richiedono nuove misure. Correlazioni monouso, journal e KV di sessione
non sono cache da importare nella nuova esecuzione.

Il punto di partenza corrente è `campaign-20261007T163602Z/RESUME.md`:
`gamma-admission-20261007T155133Z/` contiene la ricevuta e il verificatore;
`pilot-complete`, `integer-complete`, `integer-trace` e `ledger` del 7 ottobre
contengono candidata, due replay, confronto indipendente e ricette.
Le tabelle certificate restano in
`integer-timeout-20261007T140500Z/tables-fp64-full.bin`: il nome storico
del bundle non ne invalida l'uso documentato nella ricevuta Γ.
Il RESUME storico descrive lo stato alla chiusura; per autorizzazioni,
limiti e pulizia prevalgono le regole correnti sopra.

## Gestione del pod e del repository

Usare [runpod_harness.sh](../../scripts/runpod_harness.sh) per la gestione
di un eventuale pod autorizzato. Il harness permette ispezione e chiusura;
non ha un comando di riattivazione. L'agent può usare le API RunPod
`podResume`/`podStop` per il pod autorizzato e rileggere stato, hardware
ed endpoint dopo la riattivazione: UUID, IP e porta precedenti non sono
garantiti. La [documentazione API](https://docs.runpod.io/sdks/graphql/manage-pods)
descrive queste operazioni. Registrare l'istante di riattivazione e
attivare il nuovo controllo di deadline, senza spostare l'inizio al primo SSH.
Prima di compilare o generare artefatti sul pod eseguire `scripts/runpod_harness.sh git-preflight`, oppure verificare
lettura/scrittura Git HTTPS dalla VM, pubblicare la SHA su un branch unico
e verificare dal pod il checkout anonimo pulito di quella stessa SHA.
Questa alternativa conserva le credenziali sulla VM e pubblica le evidenze
piccole dalla VM dopo il trasferimento del bundle autorizzato.

Sincronizzare repository ed evidenze piccole solo tramite Git HTTPS su
`https://github.com/okrame/volta-zk.git`. Le sorgenti pubbliche si leggono
anonimamente. Per pubblicare dal pod usare il Secret RunPod `VOLTA_GITHUB_TOKEN`,
con scadenza e permesso Contents read/write limitato al repository.
Non copiare credenziali dalla VM al pod, non usare gh, Git SSH, SCP/rsync o
archivi del repository per sincronizzare il codice. Si possono trasferire
via SSH gli artefatti selezionati: report/scale e binari compatibili verso
il pod, evidenze chiuse verso la destinazione persistente entro il tetto.
Questo riuso non trasferisce un checkout o credenziali; conservare digest
e SHA di build dei binari, distinti dalla SHA corrente. Le evidenze piccole
revisionate sono poi pubblicate tramite Git HTTPS. Token fuori da URL, configurazioni Git, comandi,
cronologia e file; il wrapper usa askpass. Un eventuale Secret HF è
separato e di sola lettura. Verificare la SHA pulita dopo ogni pull.

```text
scripts/runpod_harness.sh list
scripts/runpod_harness.sh status POD_ID
scripts/runpod_harness.sh pause POD_ID
scripts/runpod_harness.sh delete POD_ID --confirm POD_ID
```

`pause` arresta il pod e libera la GPU; il disco del container è effimero,
mentre un volume persistente sopravvive allo stop. Verificare i mount effettivi; non dedurre persistenza dal solo nome
`/workspace`. `delete` è distinto dall'arresto, distrugge i dati del volume
locale e non è incluso nella sola autorizzazione di riattivazione/arresto.
I tipi di storage sono descritti nelle
[specifiche RunPod](https://docs.runpod.io/pods/storage/types).
Pesi e grandi artefatti non vanno in Git. Pubblicare codice ed evidenze piccole revisionate su un branch dedicato
come `runpod/POD_ID/c71-TASK-DATE` secondo la preautorizzazione sopra,
senza force-push. Per preparazione locale è ammesso un branch dedicato al task.

## Parità e misure rappresentative

Il diagnostico [c71_nonlinear_parity.cu](../../cuda/c71_nonlinear_parity.cu)
confronta kernel reali con interi host: dense MMA su tre shape (ragged e
K=21504), Affine/Gate, tutti i 65.535 entry lookup, istogrammi, entrambe
le famiglie RoPE, argmax/tie, RMS/overflow e QK→RNE→EXP30→PV nei tre
contesti con futuro KV avvelenato. QK/PV sono interi scalari, non MMA.
Compilare localmente se il toolkit è disponibile, altrimenti sul pod;
eseguire sulla H100 autorizzata e ripetere la parità alla nuova sessione:

```bash
nvcc -std=c++17 -O2 -arch=sm_90 --cudart static \
  cuda/c71_nonlinear_parity.cu cuda/c71_dense_i16.cu \
  -o /tmp/c71_nonlinear_parity
(test "$(ulimit -H -v)" = unlimited; ulimit -S -v unlimited;
 timeout -k 5s 60s /tmp/c71_nonlinear_parity)
```

Richiede compute capability 9; errore CUDA o differenza termina con exit
nonzero. Conservare stdout/stderr, digest del binario, SHA e fingerprint.
È parità sintetica `credit:false`, non un forward canonico o un benchmark.
Il test seguente è ignorato nelle suite locali e usa **la libreria reale**,
non il driver simulato: verifica gather residente→range/GKR→PCS sui MAC
originali due volte nello stesso owner, poi range signed, contro transcript
CPU ridotti. Impostare binario e `LIBRARY` a build verificate e compatibili
con le sorgenti numeriche correnti, registrando la SHA di ciascuna build;
le sole modifiche documentali non impongono ricompilazione. Eseguire:

```bash
(test "$(ulimit -H -v)" = unlimited; ulimit -S -v unlimited;
 C71_NATIVE_PARITY_LIBRARY="$LIBRARY" timeout -k 5s 60s "$C71_PCS_TEST_BINARY" \
   c71_b12_windowed_native_hardware_parity_explicit --ignored --test-threads=1 --nocapture)
```

Non richiede pesi reali; la sua disponibilità non dichiara già passata
la parità hardware. Il test locale equivalente usa lo stesso helper con
driver host simulato e non viene contato come esecuzione GPU.
Misurare sali, scansioni, accumuli, FFT, Merkle, aperture, GKR e Seed6
separatamente, poi con gli stati simultaneamente vivi. La telemetria
privata è fuori dal transcript; conservare contatori e log anche su timeout.
I cambi di geometria sono ammessi con parità e conto completo secondo il
[design](design.md#risultati-attuali-e-prossime-ottimizzazioni).
Prima di usare credenziali eseguire `scripts/runpod_harness.sh local-secret-preflight`;
un eventuale `.env` deve essere regolare, posseduto dall'utente e `0600`.

## Esperimento della prova

Il comando è ora `c71_canonical_reference experiment-cuda`. Gli esempi
`c71_matrix` e `c71_calibration` non lo sostituiscono. L'esperimento usa
la pipeline mista dichiarata, distinguendo commitment iniziali residenti
da sampler, aperture e PCS successive CPU.
Usare le
[build mirate](local-tests.md#compilazione-mirata) e la
[build della libreria CUDA](local-tests.md#collegamento-del-runner-cuda).
La campagna rispetta il budget comune descritto nelle
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

Parità hardware, tempo H100 e picco fisico si verificano nella campagna
autorizzata, con parità prima della prova completa; non sono gate locali. Il target di 65 s non è un gate preventivo per l'esperimento
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
fissare prima `CUDA_VISIBLE_DEVICES` all'UUID autorizzato,
`AUTHORIZED_END_EPOCH` e `CLOSE_RESERVE_SECONDS` dalla campagna. I limiti di
durata del processo non sostituiscono lo spegnimento entro il termine massimo.

```bash
set -euo pipefail
set -C
umask 077
test "$(git rev-parse HEAD)" = "$APPROVED_SHA"
test -z "$(git status --porcelain --untracked-files=all)"
test "$PROOF_SECONDS" -gt 0
test "${CLOSE_RESERVE_SECONDS:?riserva concordata richiesta}" -gt 0
test $(( $(date +%s) + PROOF_SECONDS )) -le \
  $(( ${AUTHORIZED_END_EPOCH:?deadline richiesta} - CLOSE_RESERVE_SECONDS ))
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
test "$(ulimit -H -v)" = unlimited
ulimit -S -v unlimited
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
Conservare anche `$RUN/journals.progress.jsonl`, privato e durevole, con
fasi, avanzamento, lavoro, traffico e campioni congiunti. Un'ultima riga
troncata resta nel file originale e si esclude dalla lettura. Il log non
misura il picco fisico HBM/bus né abilita il riuso dello stato.
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
eseguito deve essere pulita. L'istruzione del proprietario autorizza i trial
della nuova sessione entro la sua deadline; i record storici non la sostituiscono.
Aggiornare i cinque documenti correnti solo quando cambia un fatto,
collegando la nuova evidenza senza sovrascrivere quella precedente.

## Campagna di calibrazione

Seguire questo ramo solo quando Γ manca o l'ammissione pertinente viene
invalidata secondo il [riuso](#riuso-del-bundle). I cinque controlli sotto
sono già PASS per gli input pinned del 7 ottobre. Un nuovo trial valuta
una sola candidata; modificare scale o semantica richiede nuovi controlli,
partendo da O=0. Un altro host CPU non è implicito nell'hardware autorizzato.

### Accelerazione dell'inizializzatore

Sono disponibili pilot NumPy/BLAS CPU e cuBLAS FP64 H100, replay intero
Rust CPU/CUDA e confronto indipendente Python/C11. Per modificarli misurare
prefissi identici (`profile --profile-tokens N`), valori, scale/token,
causalità, rifiuti e risorse. La parità FP64 non va chiamata bitwise quando
ci sono differenze; l'ammissione richiede replay e confronto interi esatti.
Per build e fixture usare [specs](specs.md#calibrazione-prima-dellinstallazione)
e [local-tests](local-tests.md#semantica-calibrazione-e-contabilità).
`profile-matrix` e `profile-attention` sono screen; worker del pilot e del
confronto indipendente vanno scelti con confronto esatto, memoria e tempi.
BLAS/OMP/Rayon restano a un thread salvo il pool esplicito misurato.
Conservare progressi privati anche su errore, senza valori W/A/KV nei log
pubblici o nuovi messaggi al verificatore. La prova non usa BF16/TF32.

### Risorse

| Risorsa | Controllo prima del download/run |
|---|---|
| Compute | Singola H100 80 GB; per calibrazione almeno 20 vCPU e 125 GB RAM host, verificati sul pod autorizzato |
| Software | Linux x86_64, Python ≥3.11, NumPy, pytest, Rust/Cargo, C/C++, CUDA, Git, timeout/time; registrare versioni e immagine effettiva |
| Disco | Almeno 180 GB liberi prima del download completo e ≥20 GB di riserva; verificare mount e persistenza |
| Pesi | Shard 62.546.338.248 B + packed 61.394.690.560 B; nessuna seconda copia dequantizzata completa |
| Memoria offline | Ingest nativo 3.355.443.200 B operativi, payload nominato del trial ≤8 GiB; AS CPU/CUDA secondo le regole sopra |
| Traccia privata | Riservare 44 GB quando serve un nuovo confronto completo; fuori da Git e dal bundle esterno |

Stop per OOM, swap sostenuto, RSS aggregato >96 GiB, spazio libero <20 GB
o deadline. Questi limiti della calibrazione non sostituiscono l'arena
comune della prova. Contare W residente separatamente dai temporanei,
misurando anche cgroup/cache OS e HBM. Il pack nativo verifica header,
corpi shard e output persistito; i requisiti del pack Python legacy non
si applicano a `pack --native-packer`.

### Budget delle fasi

Ripartire la durata autorizzata fra ambiente, eventuale download/ingest,
pilot, tabelle, due replay, confronto indipendente, ledger, eventuale
prova e chiusura. Misure precedenti e stime non sono timeout obbligatori.
Ogni fase deve rientrare nel tempo residuo prima della riserva di chiusura;
al primo errore saltare le fasi dipendenti e conservare il fallimento.
Nuovi trial sono coperti dalle regole della campagna, senza riuso di stato.

### Identità degli input

Usare esclusivamente [checkpoint, shard, digest e workload delle specifiche](specs.md#input-e-identità),
mai `main`. I comandi importano le stesse costanti da
[c7_d126_gemma_weight_ingest.py](../../scripts/c7_d126_gemma_weight_ingest.py).
Nessun dataset nuovo, imposizione dei token prodotti dal pilot floating
o certificazione di qualità generale. Accesso HF/licenza deve essere già
valido; un 401/403 ferma la fase, senza accettare licenze o cambiare checkpoint.

### Comandi per un trial autorizzato

Gli snippet sono esempi per la calibrazione condizionale; i timeout sono
massimi da adattare alla finestra autorizzata. Il percorso principale di
riuso salta le fasi già valide. Per un ambiente nuovo impostare `APPROVED_SHA`,
`AUTHORIZED_END_EPOCH` e `CLOSE_RESERVE_SECONDS` dalla campagna corrente.
Riutilizzare un checkout esistente soltanto dopo verifica, senza sovrascrivere.

```bash
set -euo pipefail
set -C
umask 077
git clone https://github.com/okrame/volta-zk.git /workspace/volta-zk
cd /workspace/volta-zk
git checkout --detach "$APPROVED_SHA"
# Il preflight Git HTTPS dalla VM con checkout anonimo verificato sul pod
# è l'alternativa al Secret VOLTA_GITHUB_TOKEN, descritta sopra.
export ROOT=$PWD
export CAMPAIGN_LABEL=$(date -u +%Y%m%d-%H%M%S)
export RUN=/workspace/c71-gamma-$CAMPAIGN_LABEL
mkdir "$RUN"
mkdir "$RUN/logs"
export SHARDS="$RUN/weights"
export PACKED="$SHARDS/gemma-4-31b-5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89.packed.i16"
export CARGO_TARGET_DIR="$ROOT/rust/target" CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_DEV_OPT_LEVEL=2
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 RAYON_NUM_THREADS=1
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$ROOT/scripts"
test "${AUTHORIZED_END_EPOCH:?termine autorizzato richiesto}" -gt "$(date +%s)"
test "${CLOSE_RESERVE_SECONDS:?riserva di chiusura concordata richiesta}" -gt 0
export CAMPAIGN_END_EPOCH=$((AUTHORIZED_END_EPOCH - CLOSE_RESERVE_SECONDS))
test "$(ulimit -H -v)" = unlimited
ulimit -S -v 67108864
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
Se l'immagine effettivamente in esecuzione non espone un digest, registrare
la lacuna; non sostituirlo con quello di un tag risolto altrove.
Questi snippet registrano durata/HWM, non il census fisico completo:
affiancare monitor congiunto RSS dell'albero/HBM, cgroup/swap, spazio libero
e capacità trattenute. Verificare che l'arresto del monitor termini anche
i sottoprocessi/gruppi della sessione, inclusi quelli creati da `timeout`.

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

Le versioni sono esempi riproducibili della campagna precedente; registrare
quelle effettive, senza upgrade impliciti. I piccoli controlli restano
60 s / 2 GiB; se il linker vede molti core, limitarne l'affinità a un core
per rispettare l'AS. Nessun workspace E2E sulla VM locale.

### Download e ingest

Verificare prima i file esistenti. Con shard assenti usare una directory
`SHARDS` nuova: lo script crea la directory, scrive `.partial`, verifica
gli hash pinned e pubblica senza sovrascrivere. Un 401/403 ferma la fase;
nessuna accettazione implicita di licenze o cambio di checkpoint.

```bash
run_step 1800 download .venv/bin/python scripts/c71_download_weights.py
run_step 1800 ingest .venv/bin/python scripts/c7_d126_gemma_weight_ingest.py pack \
  --shard-dir "$SHARDS" --output "$PACKED" \
  --native-packer "$CARGO_TARGET_DIR/gemma31b_bf16_pack"
export INGEST="$RUN/logs/ingest.stdout"
chmod a-w "$SHARDS"/*.safetensors "$PACKED"
```

`PACKED_UNADMITTED` con corpi/hash verificati è l'esito corretto dell'ingest:
non è ancora ammissione Γ. Conservare gli esiti dei tentativi interrotti.

### Pilot, tabelle e due replay interi

Il comando pilot sotto è la baseline CPU seriale (`--matrix-workers` ha
default 1), non la scelta obbligatoria per il nuovo trial. Usare il percorso
e la configurazione accelerati dopo i confronti e le misure sopra.
I timeout 5.400/5.100 s sono massimi di esempio; allocare tempi compatibili
con tutte le fasi residue, senza estendere la deadline complessiva.

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
esplicita della nuova sessione copre i trial previsti entro gli stessi limiti,
senza cambiare relazione, trust model o requisiti di validazione.

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
lettura di verifica. Conservare le tabelle utili al riuso o verificarne la rigenerazione dalle
ricette; i dump privati restano sul pod e non entrano in Git o nel bundle
esterno, soggetto al tetto cumulativo di 10 GB e alla pulizia sopra.

Preparare `EXPORT` come directory nuova contenente soltanto la selezione
da conservare fuori dal pod: file chiusi, senza shard, packed o tracce
grandi. Controllarne la dimensione rispetto allo spazio residuo del tetto
complessivo di `artifact/c7.1-pod/`. Il manifest seguente riguarda questa
selezione, non l'intero RUN con la traccia privata.

```bash
RUN="${EXPORT:?directory di export selezionata richiesta}" .venv/bin/python - <<'PY'
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
Pubblicare secondo la procedura Git HTTPS scelta. Con Secret sul pod,
il comando è il seguente; con il preflight alternativo, commit e push
si eseguono dalla VM verso lo stesso branch autorizzato:

```bash
scripts/runpod_harness.sh git-preflight
scripts/runpod_harness.sh git-push "runpod/$RUNPOD_POD_ID/c71-calibration-$CAMPAIGN_LABEL"
```

Alla chiusura della campagna, verificare da un checkout remoto separato
il commit e i file pubblicati, e la destinazione autorizzata dei dati da
conservare, prima dell’arresto della [gestione pod](#gestione-del-pod-e-del-repository);
il `delete` è distinto e richiede che i dati da conservare siano già verificati.
Resta vincolante il termine concordato, anche se il salvataggio è incompleto.
Dopo l'ammissione di Γ, portare profilo e conto delle risorse
all'[esperimento della prova](#esperimento-della-prova) se già autorizzato
e compatibile con il budget residuo. La calibrazione non misura prova/PCG
e non emette certificati.
