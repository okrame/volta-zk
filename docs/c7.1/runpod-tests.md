# C7.1 — test su RunPod

[Design](design.md) · [Specifiche](specs.md) · [Sicurezza](security.md) ·
[Test locali](local-tests.md) · [Archivio](../c7.1-history/README.md)

È autorizzato il [seguito H100 del 10 ottobre](../c7.1-history/h100-followup-start-2026-10-10.md)
sul solo pod `z6wx2kkn69eoc0`, sei ore dall'avvio provider, con trenta
minuti riservati alla chiusura: fine calcolo 21:57:24 UTC, guard
22:22:24 UTC, stop confermato entro 22:27:24 UTC del 10 ottobre
(00:27:24 Italia dell'11 ottobre). Guard indipendente attivo sulla VM.
Priorità: spike A, pool/fill separati sui caller reali, poi motore
ottimizzato e RMS coarser. Γ ammesso resta il riferimento; NoPeek,
MAC originali, AES reale, correlazioni monouso e limiti restano invariati.
Nuovi trial usano journal e capacità nuovi. Zero nuovi certificati;
bound e tempi completi restano aperti. Il [prefisso diagnostico canonico](../c7.1-history/h100-followup-spike-prefix-2026-10-10.md)
completa 35/512 gruppi A con W/setup presenti, poi esaurisce il logger
da 16 MiB. Il picco stabile campionato è 6.141.582.848 B: non è
un picco completo né una soluzione dello spike. Il trial default senza
logger/profiler è in corso, con timeout 90 minuti entro la deadline.

La [precedente campagna H100 del 9–10 ottobre è chiusa](../c7.1-history/h100-campaign-close-2026-10-10.md).
Pod spento e confermato `EXITED`, runtime assente, alle **01:49:55 UTC**
(03:49:55 Italia), entro otto ore dall'avvio provider. **Zero certificati**;
O=150/300 non iniziati. Il sesto trial completa W/setup/preparazione O=0,
poi supera il cap fisico: 6.560.767.488 B contro 6.174.015.488 B.
Tempi completi di prova/verifica e picco completo restano non misurati.

PCS W misura 190,425 s, installazione 212,418 s e setup 1.493,833 s
(−24,799% osservato rispetto al precedente). L'inferenza separata misura 84,382 s nel nostro esecutore intero esatto;
manca un confronto sullo stesso workload con un motore di inferenza
ottimizzato. A04 termina per cap fisico dopo 86/512 gruppi, wall 780,205 s.
I diagnostici A omettono lo stato W/setup e non dimostrano il picco canonico.
La causa dello spike resta aperta; il target 65 s non è raggiunto.

L'istruzione corrente sostituisce il vincolo di solo lavoro locale della
[chiusura locale](../c7.1-history/local-exploration-close-2026-10-10.md).
Autorizza correzioni, microbenchmark e trial sul pod indicato entro
ambito e deadline, senza altro hardware o estensioni. Il
[piano hardware mirato](../c7.1-history/local-hardware-plan-2026-10-10.md)
e le priorità del seguito locale guidano le misure, senza credito prima
dell'esecuzione e dei controlli pertinenti.
Le quattro candidate di scale A restano screening non ammessi, con W,
architettura, workload e ricette fissati, geometria A/PCS e 512 ricostruzioni
iniziali invariati. Γ ammesso resta il riferimento.

La modifica locale riusa un flag numerico sincrono privato da 256 B,
aggiungendo 8 B all'owner host (42.096 B nella fixture corrente, 42.088 B
nei record H100 storici). La capacità trattenuta resta conteggiata fino
al cleanup; reset per operazione, letture di errore, fence e garanzie
restano invariati. Il [preflight H100 del seguito](../../benchmarks/results/c71-h100-followup-preflight-2026-10-10-7b0885ad316f.json)
passa 15 filtri hardware e il nuovo test numerico su ciascuna delle tre
librerie; valori, copie e fence sono identici. Il beneficio di wall sui
caller reali resta da misurare. Il logger completo esaurisce 16 MiB in
2,47 s del primo gruppo A, senza completarlo. La build diagnostica con
`-DC71_OWNER_TRACE -DC71_OWNER_TRACE_LARGE_ONLY` conserva snapshot e
lifecycle da 1 MiB, omettendo fence e alloc/free minori; timeline CUDA
esterna e contabilità degli strumenti restano necessarie, stesso cap.
Il conto del setup AES reale include anche cache W
e owner già installati; NoPeek, MAC originali, correlazioni fresche,
PCG AES e fail-closed restano quelli del percorso selezionato.

## Stato e sequenza operativa

Il [seguito locale e piano aggiornato](../c7.1-history/local-followup-2026-10-10.md#verifiche-hardware-prioritarie-dopo-il-seguito-locale)
prepara la traccia owner bounded e distingue pool, padding A zero e
candidate RMS. Per attribuire lo spike servono eventi CUDA e correlation
ID del profiler esterno, oltre a live capacity e clock monotonic comuni;
il logger da solo non li produce. Fissare la finestra prima del gruppo
sospetto, verificare tasso/copertura entro 16 MiB/131.072 record e contare
owner diagnostico 42.128 B, stack, cache file/FS e profiler. Gli snapshot
all'arming sono capacità già vive; il gruppo indica l'ultimo begin
validato, comprese le allocazioni preparatorie con etichetta precedente.
Stop anche per dati persi o finestra incompleta, senza aumentare cap.
Confronti temporali senza profiler e parità CUDA reale precedono ogni
credito prestazionale. Le fasi hardware sono ora autorizzate nella nuova
campagna sopra; il prefisso diagnostico e i suoi limiti sono registrati
nella nuova evidenza collegata all'inizio.

Γ è ammesso e riusato dopo verifica dei cinque controlli, degli input e
dei tre piani pubblici. La precedente campagna sul pod è **conclusa**:
conferma provider `EXITED`/runtime assente alle 01:49:55 UTC del 10 ottobre,
dopo 6 h 41 min, prima della deadline 03:08:42 UTC.
Fine calcolo prevista 02:38:42, guard indipendente 03:03:42; ritiro del
guard solo dopo lo stop confermato. Quella campagna è terminata; la nuova autorizzazione e deadline sono
quelle riportate sopra. Codice ed evidenze sono sul branch Git HTTPS
`runpod/z6wx2kkn69eoc0/c71-h100-20261009`.

| Trial canonico | Esito conservato |
|---|---|
| [01](../c7.1-history/h100-canonical-01-2026-10-09.md) | W/setup completi; marker pubblico inutilizzato rifiutato nella preparazione |
| [02](../c7.1-history/h100-prefill-2026-10-09.md) | Stop pianificato nel caricamento: ritirato il batching più lento, prima di setup/journal |
| [03](../c7.1-history/h100-monitor-stack-2026-10-09.md) | W completo; monitor fermato da lettura smaps senza copertura W durante setup |
| [04](../c7.1-history/h100-canonical-04-2026-10-09.md) | W/setup/preparazione completi; 6.190.775.808 B oltre cap nel primo gruppo A |
| [05](../c7.1-history/h100-canonical-05-2026-10-09.md) | W/setup/preparazione completi; rifiuto del prefisso KV nel consumer A, poi corretto |
| [06](../c7.1-history/h100-canonical-06-2026-10-10.md) | W/setup/preparazione e 35 gruppi A; stop fisico a 6.560.767.488 B |

Zero certificati accettati; O=150/300 non iniziati. Nessun trial riprende
stato terminale. Il [checkpoint W/setup più recente](../c7.1-history/h100-setup06-checkpoint-2026-10-10.md)
misura PCS 190,425 s, installazione 212,418 s e setup 1.493,833 s.
Il setup migliora del 24,799% osservato rispetto al quinto trial; il record
dichiara limiti del confronto e sovrapposizioni CPU precedenti.

Selezione operativa: W Tensor esatto dopo confronto 256 MiB (5,663×),
stack iniziale 256 B verificato, W con consiglio THP, code compute/copy 1/1,
correzione degli span al prefisso originale e coda cGGM differita.
Il monitor richiede copertura smaps completa, conserva snapshot falliti,
limita le riletture (due per campione/64 fallimenti) e include il campione
terminale nel massimo. I campioni recuperati mantengono il cap ma non
ricevono credito al picco stabile. Trentasei test del monitor passano.

Il [diagnostico A03](../c7.1-history/h100-a-quarter-2026-10-10.md) con code
ridotte fallisce sul cap dopo 22 gruppi. A04 termina per cap fisico dopo 86/512 gruppi, wall 780,205 s.
L'[esito finale](../c7.1-history/h100-campaign-close-2026-10-10.md) conserva
lanci sincroni, parità reale 15/15, geometria D34, monete fresche e cap.
È un componente senza W commitment/setup/prova/promozione, non una
validazione del picco canonico. La causa dello spike rimane aperta.
I record precedenti conservano anche il rifiuto iniziale e lo stop
pianificato dopo tre gruppi. Non è previsto un altro trial in questa campagna.

Il runner `experiment-cuda` è misto: inferenza/replay/range A e commitment
iniziali W/A con sali residenti e
[query iniziali A native](../c7.1-history/crypto-query-2026-10-09.md) e
[closure lineare residente](../c7.1-history/crypto-linear-2026-10-09.md).
Il [checkpoint S1 e Query E](../c7.1-history/crypto-residual-query-2026-10-09.md)
collega anche coset/hash/sali extension, OOD, retention/fold A,
contrazioni e query extension A/W al common owner. Le
[query iniziali W](../c7.1-history/crypto-local-convergence-2026-10-09.md)
sono ora residenti; fattori pubblici, Merkle delle aperture, GKR non-range/MAC,
Seed6 AES e verifica restano CPU. Il
[checkpoint RMS](../c7.1-history/crypto-rms-close-2026-10-09.md) seleziona
replay64/DAG CPU per programmi misti senza pattern prefix, primo round
esatto e cache compatta; i coefficienti Fp3 residui restano CPU.
Il conto per fasi è nominato, `joint_admitted:false`; la
[revisione locale dei lifetime](../c7.1-history/crypto-retirement-short-merkle-2026-10-09.md)
conserva anche il timeout della prova composta.
Il [conto locale del 9 ottobre](../../benchmarks/results/c71-preh100-operational-local-2026-10-09-24b54d414421.json) includeva cache/workspace
RMS e il campo di lifecycle W: massimo storico 5.878.734.842 B e 26.845.190 B
residui nel payload. La [chiusura locale del 10 ottobre](../c7.1-history/local-exploration-close-2026-10-10.md)
aggiorna flag trattenuto, owner e stato W già vivo durante il setup AES
reale: massimo nominato corrente 5.878.735.106 B, con 26.844.926 B residui,
senza credito di picco fisico. Prima del trial usare questo conto. Il manifest del
trial deve vincolare capacità dei path/argv ≤4.096 B e identità
Γ/layout/toolchain applicabili; non trasformare questa premessa in
un'allocazione gratuita. Ricontare nuove modifiche prima del trial;
misurare allowance, residenza fisica e margine congiunto sulla H100.
La parità lineare ridotta passa; il test completo KV e la catena AES
composta conservano timeout locali. Questi non sono risultati hardware.
Accumulo W Tensor è ora selezionato; QK/PV resta scalare. Il confronto
misurato W non attribuisce prestazioni della prova completa. I piccoli
diagnostici osservano circa 550 MB GPU: l'allowance runtime 256 MiB rimane
non dimostrata, e il monitor canonico conserva il tetto fisico originale.

Percorso principale: verificare codice/procedure locali → autorizzare
hardware e durata → verificare ambiente e riusare Γ → parità CUDA e
misure rappresentative con conto simultaneo → esperimento O=0/150/300 →
conservare esiti e arrestare il pod. La campagna misura separatamente
installazione W, setup di sessione, inferenza, prova e verifica. La
[calibrazione](#campagna-di-calibrazione) è un ramo condizionale, richiesto
quando l'ammissione pertinente è invalidata; la prova completa richiede
Γ ammesso. Cronache, pod/deadline e stime superate rimangono nel
[runbook storico](../c7.1-history/runpod-tests-2026-10-07.md).

### Preparazione operativa della campagna

La revisione su `c5b81bf` ha individuato tre lacune del passaggio hardware;
le correzioni sono implementate nel codice e nelle procedure correnti.
La [chiusura locale](../c7.1-history/crypto-preh100-operations-2026-10-09.md)
registra 65 test passati e il conto aggiornato, prima di qualsiasi nuova
autorizzazione hardware:

1. **Ingressi CUDA espliciti.** Quattordici test positivi `#[ignore]`
   riusano gli oracoli host per sali/FFT, commitment/query W/A, closure
   lineare e S1/Query E. La guard comune richiede
   `C71_NATIVE_PARITY_LIBRARY` assoluta e rifiuta i simboli della libreria
   simulata anche se rinominata. I test locali restano simulati; fault
   injection e simboli mancanti non vengono trasferiti sulla GPU.
   I comandi individuali sono [sotto](#parità-e-misure-rappresentative).
2. **Trasporto diagnostico.** Il runner accetta
   `C71_DIAGNOSTIC_TIMEOUT_SECONDS`, intero positivo u32, default 65 s.
   Il monitor lo imposta alla durata della fase, mantenendo finite le
   attese read/write e terminali timeout/disconnessioni. La deadline
   esterna ferma l'intero esperimento; il target prestazionale rimane 65 s.
3. **Lancio sorvegliato.**
   [`c71_campaign_measure.py`](../../scripts/c71_campaign_measure.py)
   distingue `--mode canonical` da `--mode calibration`, richiede deadline,
   riserva di chiusura esplicita, UUID GPU e cgroup v2 leggibile
   (`memory.events`/`memory.current`). Errori del monitor, OOM, swap,
   disco/margini GPU e superamento dei temporanei campionati fermano la
   sessione con i gruppi figli. I metadati CPU/GPU del runner riflettono
   le route residenti correnti; rimangono etichette, non misure di kernel.

Il conto fisico stabile include RSS dell'albero e monitor più HBM del
device intero. Per W host sottrae solo un limite inferiore della residenza
ricavato da `smaps`; per W device richiede il lifecycle dell'owner del run.
Durante allocazione/ritiro non concede credito al campione congiunto:
restano deadline e stop globali, ma quel tratto non prova il tetto fisico.
Il report conserva `physical_complete_peak:false`. Picchi transitori,
sufficienza della riserva fisica e cinque tempi richiedono la campagna.
Il monitor del processo non spegne il pod: serve sempre il guard provider
indipendente e la conferma finale dello stop.
Il lancio richiede Linux con `/proc` e `smaps` leggibili per lo stesso UID,
cgroup v2 con `memory.current`/`memory.events`, GNU `/usr/bin/time` e
`nvidia-smi` sul device autorizzato. Dati o dipendenze mancanti fermano
il controllo; non vengono sostituiti con zeri.

Questi interventi preservano Γ, protocollo, limiti e NoPeek/MAC originali.
La validazione locale riguarda le guardie e gli oracoli ridotti; nessun
esito locale attribuisce compilazione CUDA o parità sulla H100.

## Autorizzazione e limiti

Regole permanenti approvate dal proprietario l'8 ottobre 2026;
[motivazione e decisioni](../c7.1-history/operating-rules-2026-10-08.md).
L'istruzione corrente del proprietario autorizza la nuova campagna sul
solo pod `z6wx2kkn69eoc0`, massimo sei ore dall'avvio provider e
trenta minuti di chiusura inclusi, con ambito e priorità definiti sopra.
Altra durata o hardware richiedono una nuova decisione.

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
richiede `AUTHORIZED_END_EPOCH`, `CLOSE_RESERVE_SECONDS` e UUID in
`CUDA_VISIBLE_DEVICES`; il suo arresto raggiunge i gruppi figli nella
sessione. Usare il modo canonico e il progress log secondo la
[procedura](#preparazione-operativa-della-campagna). Il timeout di un processo non spegne
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

Il [metodo dei nuovi confronti](../c7.1-history/h100-comparison-plan-2026-10-10.md)
fissa precisioni/backend, teacher forcing, generazione libera e criteri
dello screen RMS prima dei risultati. Il diagnostico SDPA usa un ambiente
Python isolato e il medesimo checkpoint/workload, con monitor calibration
e limiti globali; non viene eseguito insieme al runner canonico GPU.
W load, warmup, prefill, decode, wall totale e capacità retained rimangono
separati, senza credito di protocollo o di ammissione Γ.

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
I test seguenti sono ignorati nelle suite locali e richiedono **la
libreria reale**. Il range verifica gather residente→range/GKR→PCS sui
MAC originali due volte nello stesso owner, poi range signed. Gli altri
14 ingressi confrontano i nuovi consumer con gli stessi oracoli host.
Impostare binario e `LIBRARY` a build verificate e compatibili
con le sorgenti numeriche correnti, registrando la SHA di ciascuna build;
le sole modifiche documentali non impongono ricompilazione. Eseguire:

```bash
set -euo pipefail
test "$(ulimit -H -v)" = unlimited
ulimit -S -v unlimited
C71_HARDWARE_FILTERS=(
  c71_b12_windowed_native_hardware_parity_explicit
  c71_b12_native_hardware_transform_natural_forward_inverse
  c71_b12_native_hardware_private_salts_stream_and_hash
  c71_b12_native_hardware_weight_tree_roots_openings
  c71_b12_native_hardware_source_tree_roots_openings_histogram
  c71_b12_native_hardware_initial_source_query_horner
  c71_b12_native_hardware_initial_weight_query_horner
  c71_b12_native_hardware_initial_source_query_whir_chain
  c71_b12_native_hardware_residual_state_retention_and_views
  c71_b12_native_hardware_residual_tree_roots_salts_openings
  c71_b12_native_hardware_residual_query_horner
  c71_b12_native_hardware_residual_source_whir_chain
  c71_b12_native_hardware_residual_weight_whir_chain
  c71_b12_native_hardware_linear_coefficients_endpoints
  c71_b12_native_hardware_linear_full_wire_fs_point_and_original_mac
  c71_b12_native_hardware_numeric_flag_and_public_zero
)
for C71_HARDWARE_FILTER in "${C71_HARDWARE_FILTERS[@]}"; do
  test $(( $(date +%s) + 60 )) -le \
    $(( ${AUTHORIZED_END_EPOCH:?deadline richiesta} - ${CLOSE_RESERVE_SECONDS:?riserva richiesta} ))
  test "$("$C71_PCS_TEST_BINARY" "$C71_HARDWARE_FILTER" --ignored --list | awk '/: test$/ { n++ } END { print n+0 }')" = 1
  C71_NATIVE_PARITY_LIBRARY="$LIBRARY" timeout -k 5s 60s "$C71_PCS_TEST_BINARY" \
    "$C71_HARDWARE_FILTER" --ignored --test-threads=1 --nocapture
done
```

Non richiedono pesi reali; la disponibilità non dichiara già passata la
parità hardware. Eseguire un filtro per processo e conservare l'esito:
zero test eseguiti o timeout non sono pass. Le catene WHIR D10 hanno
commitment iniziale CPU dichiarato e query/S1/extension native;
commitment iniziali GPU e aperture W/A sono coperti separatamente D15.
Questi test devono essere ripetuti sul codice corrente; Tensor W è già
selezionato dopo la parità e il confronto H100. Le candidate attention
restano non selezionate. Le fixture locali equivalenti rimangono host
anche con la variabile d'ambiente impostata.
Misurare sali, scansioni, accumuli, FFT, Merkle, aperture, GKR e Seed6
separatamente, poi con gli stati simultaneamente vivi. La telemetria
privata è fuori dal transcript; conservare contatori e log anche su timeout.
I cambi di geometria sono ammessi con parità e conto completo secondo il
[design](design.md#risultati-attuali-e-prossime-ottimizzazioni).
Prima di usare credenziali eseguire `scripts/runpod_harness.sh local-secret-preflight`;
un eventuale `.env` deve essere regolare, posseduto dall'utente e `0600`.

La futura libreria completa segue la
[build locale](local-tests.md#collegamento-del-runner-cuda), includendo
hash, weight, Tensor, source, sali/query PCS, unità lineare e le due
unità residuali oltre all'owner. Simboli ABI4
mancanti sono terminali, senza fallback. Verificare CUDA reali di
prescan prefix/scatter, replay sali, seek/rejection/cap, cursor finali,
flag/fence, basi, pad e root. Verificare anche FFT naturali pari/dispari,
inverse e segmenti batch; le fixture host non eseguono quei kernel.
Per le query iniziali W/A confrontare tutte le valutazioni con Horner e
gli stessi intervalli del reader, inclusi live parziale/zero, pad,
duplicati ed ordine invertito. Richiedere zero D2H dei byte originali e
riuso dello stesso owner; ripetere la catena uncached con wire/FS/RNG e
MAC originali. Contare fattori/staging CPU, matrice finale, righe/sali/path
già aperti e gli altri owner secondo [specs](specs.md#aperture-e-fft-naturale).
Verificare il ritiro dello scratch query prima della rigenerazione del
batch corrente e retention S1 solo dopo apertura del predecessore.
Per W verificare il nuovo simbolo, packed sigillato, mapping/live prima
dell'indirizzo e zero upload degli originali. Usare le vere query Merkle:
512 foglie espandono sottoalberi da 4096 righe, fino a due batch q_eff=2^20.
Misurare separatamente fattori CPU, remainder/FFT dispari, packing D2D,
matrice finale e hash della rigenerazione. Per RMS confrontare packed e
letterale sugli stessi circuiti/assegnamenti nonzero del Γ ammesso:
wire/FS/RNG, coefficienti r0, endpoint byte, padding e consumo monouso.
Registrare separatamente plan build, replay Booleano64, coefficienti
Fp3 ed endpoint del caller; i 998.927.195.904 callback per risposta
sono invariati. Un profilo CUDA della PCS non misura il servizio CPU GKR.
Per la closure lineare confrontare coefficienti/endpoints e intero wire
dei MAC originali, contando 124 B e due fence del consumer per round
separatamente dai producer. Verificare mapping W unico, scanner A
senza lock esterno, ritiro prima della pubblicazione e assenza di
consumo correlazioni sui round falliti. Il checkpoint locale non
compila CUDA. Gli ingressi hardware espliciti
`c71_b12_native_hardware_linear_coefficients_endpoints` e
`c71_b12_native_hardware_linear_full_wire_fs_point_and_original_mac`
esistono e sono passati nella campagna H100 chiusa; ripeterli sul codice
corrente in una nuova campagna autorizzata. Non rilanciare
i filtri simulati attribuendo loro credito CUDA. Per S1 ripetere
singleton/OOD, codec, contrazioni e fold contro
l'oracolo PCS indipendente; verificare retention dopo apertura del
predecessore e old+new fino al retirement, senza duplicato host S1.
Per Query E ripetere Horner in tutti gli stadi, prefissi virtuali 0..2,
ordinalità/generazione delle plane, lineage, pad e getter privati vietati.
Misurare launch/lavoro del loader W parallelo, zero D2H degli originali,
nessuna ricostruzione A aggiuntiva e publication/staging simultanei.
Il ledger completo deve riusare tutte le classi tipate e i lifetime
delle [specifiche](specs.md#runner-cuda-sperimentale-e-conto-simultaneo),
misurando allowance e picco fisico simultaneo, senza sommare subtree
o scratch già ritirati.
Per l'hash extension ripetere foglie/nodi/root contro BLAKE3 pinned,
copertura logica 2R con output R e bande senza attraversamento di lane.
Contare i batch W soltanto fino alla chiusura W; capacità di proof/codec,
wire e realloc restano esplicite. Un cap sulla lunghezza del certificato
non prova una capacità Vec né il completamento entro il budget.

Il [diagnostico W](../../cuda/c71_pcs_weight_compare.cpp) si compila e
linka contro la libreria CUDA reale, rifiutando il driver di test.
Confronta tutte le word canoniche postFFT e tutti i digest contro oracle
indipendente; una warmup e tre rep alternate per gruppo, stesso owner e
input, misurano accumulo+FFT+fence con contatori e memoria completi.
W sintetica da 4 MiB, R64/Q256, 128 colonne e gruppi 0/4064 sono un
componente che entra in L2: quei tempi non sostituiscono W pinned.
Non eseguire prima dell'autorizzazione hardware/durata.

Le candidate QK/PV richiedono compilazione e parità reali anche sulle
letture causali per riga, con future già inizializzate; il default
scalare rimane il confronto. Selezionare ordinario/Tensor e attention
secondo misure rappresentative, senza inferire speedup dal driver host.
Misurare separatamente installazione, setup, inferenza, prova e verifica;
quantificare i colli residui, incluso il core RMS CPU. Valutare TMA,
fusioni e CUDA Graphs solo con parità, risorse e beneficio misurati.

## Esperimento della prova

Il comando è ora `c71_canonical_reference experiment-cuda`. Gli esempi
`c71_matrix` e `c71_calibration` non lo sostituiscono. L'esperimento usa
la pipeline mista dichiarata, con commitment iniziali W/A, query iniziali
W/A e PCS residuale/query extension residenti; fattori pubblici e Merkle
delle aperture restano CPU.
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
autorizzata, con parità prima della prova completa; non sono gate locali.
Gli ingressi di test e il lancio sorvegliato sono definiti nella
[procedura operativa](#preparazione-operativa-della-campagna).
Il target di 65 s non è un gate preventivo per l'esperimento diagnostico;
il monitor imposta un timeout socket diagnostico finito separato.
Misurare e conservare anche il mancato target. Rimangono
invariati NoPeek, MAC originali, margine arena 256 MiB, margine globale
1 GiB e stop su esaurimento senza spill dinamico.

Gli esperimenti GPU confrontano prima gli operatori con il diagnostico
di parità sopra e il range con il riferimento host/nativo. Accumuli,
FFT e hash salato dei commitment iniziali, lettore e resti delle query
iniziali W/A, S1 e query extension sono residenti; fattori pubblici e
rigenerazione Merkle restano CPU nel checkpoint validato. Poi si
misurano le fasi rappresentative con i
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
export CUDA_VISIBLE_DEVICES AUTHORIZED_END_EPOCH CLOSE_RESERVE_SECONDS
mkdir "$RUN"
nvidia-smi -q > "$RUN/hardware.txt"
nvcc --version > "$RUN/nvcc.txt"
rustc -vV > "$RUN/rustc.txt"
sha256sum "$LIBRARY" rust/target/debug/examples/c71_canonical_reference \
  > "$RUN/executables.sha256"
test "$(ulimit -H -v)" = unlimited
ulimit -S -v unlimited
.venv/bin/python scripts/c71_campaign_measure.py \
  --mode canonical --progress "$RUN/journals.progress.jsonl" \
  "$RUN" canonical "$PROOF_SECONDS" \
  rust/target/debug/examples/c71_canonical_reference experiment-cuda \
  "$CANDIDATE" "$TABLES" "$PACKED" "$RUN/journals" 2147483648 "$LIBRARY" 0
```

Il wrapper crea esclusivamente `$RUN/logs/canonical.*`: stdout/stderr,
`memory.csv`, `time.txt`, exit e `summary.json`. Osserva il device intero,
non attribuisce HBM a un ruolo; un campione GPU/cgroup mancante o invalido
ferma la sessione. `time -v` registra CPU-time/RSS del processo con
entrambi i ruoli. Il timeout resta un fallimento anche senza JSON finale.
Conservare anche `$RUN/journals.progress.jsonl`, privato e durevole, con
fasi, avanzamento, lavoro, traffico e campioni congiunti. Un'ultima riga
troncata resta nel file originale e si esclude dalla lettura. Il log non
misura il picco fisico HBM/bus né abilita il riuso dello stato.
Le milestone `pcs_a_resident` con `work.boundary:start/end` conservano
entrambi i confini di ciascun gruppo, senza throttle, e i relativi contatori.
Usarle per confronti di prefissi completi e per armare finestre profiler;
un arresto dopo una milestone resta un run incompleto, senza commitment
pubblicato, prova o accettazione. Contare anche il costo della diagnostica.
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
