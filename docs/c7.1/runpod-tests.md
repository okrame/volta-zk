# C7.1 — test su RunPod

[Design](design.md) · [Specifiche](specs.md) · [Sicurezza](security.md) ·
[Test locali](local-tests.md) · [Archivio](../c7.1-history/README.md)

## Stato e sequenza operativa

Il runner locale `experiment-cuda` collega inferenza/replay dei 13 producer,
owner comune, range residente, PCS/GKR CPU, verifica e promozione per
O=0/150/300. L'esperimento canonico richiede ancora Γ ammesso e
autorizzazione hardware valida. Nessun certificato canonico, tempo completo
o rispetto dei target è acquisito. Gli audit delle revisioni precedenti
restano nei record storici e non introducono gate concorrenti.

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

**Ultima campagna, conclusa il 4 ottobre 2026.** Pod `z3h2njpctmduix`, H100;
inizio 17:07:53 UTC, termine autorizzato 23:07:53 UTC. L'arresto è stato
gestito dall'agente e verificato alle 21:01:31 UTC. La vecchia deadline,
il guard e la preautorizzazione dei trial sono evidenza storica e non
vanno riutilizzati per avviare una nuova sessione.

**Conservazione.** La destinazione esterna autorizzata è
`/home/okrame/projects/volta-zk/artifact/c7.1-pod/`, con **tetto complessivo
10.000.000.000 B**. Conservare calibrazione verificata, ricette/tabelle,
identità/hash, codice/ambiente, report, log e manifest; non copiarvi shard,
packed o tracce grandi. Verificare eventuali pesi presenti sul pod e
ricrearli se mancanti o incompatibili, confrontando le identità complete.
La calibrazione completata resta
riutilizzabile secondo i controlli sotto; una nuova H100 richiede comunque
compatibilità, parità e nuove misure fisiche.

**Ultimo esito: [INCOMPLETO](../../benchmarks/results/c71-h100-diagnostic-checkpoint-2026-10-04-e3f08e939eef.json), `credit:false`.**
Ambiente/build, parità sintetica CUDA e percorso ridotto sui MAC originali,
ingestione reale e 29 controlli numerici sono PASS. Il pilot readonly-mmap
con otto worker termina per timeout interno di 5.100 s (wall 5.153,79 s),
senza candidata: Γ, tabelle/ricette certificate, confronto indipendente,
due replay interi e O=0/150/300 non sono acquisiti. Tempi canonici e byte
dei certificati restano nulli. Il massimo RSS+HBM campionato è
62.255.046.656 B inclusa W; picco temporaneo completo e margine canonico
non verificati. Digest dell'immagine effettiva e attribuzione di 29 campioni
HBM non nulli restano aperti. Tutti i fallimenti sono conservati nei record
collegati e nei dieci bundle verificati, 106.904.206 B alla chiusura,
senza shard/packed. La ripresa è descritta in
`artifact/c7.1-pod/campaign-20261004T170753Z/RESUME.md` dalla radice del repo.

**Prossima sessione.** L'istruzione di affidamento deve autorizzare la
riattivazione del pod, le modifiche per accelerare l'inizializzatore,
download, calibrazione e diagnostica condizionata all'ammissione di Γ.
Quando quell'istruzione è ricevuta, i trial previsti sono coperti senza
una nuova conferma per ciascuno. Analizzare codice ed evidenze localmente
prima della riattivazione; i limiti locali restano quelli di
[local-tests](local-tests.md#limiti-e-ambiente).
Registrare una nuova deadline di 6 ore dalla riattivazione, inclusi
ambiente, verifiche e salvataggio, con almeno 30 minuti di riserva;
l'agent gestisce l'arresto e ne verifica lo stato dal provider.
Nessuna proroga, seconda macchina o modifica del trust model è implicita.
L'ordine è [accelerazione misurata](#accelerazione-dellinizializzatore),
[cinque controlli di ammissione](#validazione-e-congelamento-del-profilo),
poi [diagnostica O=0/150/300](#esperimento-della-prova) se il tempo residuo
lo permette. Un prerequisito mancante lascia aperte le fasi dipendenti;
conservare sempre esito e copertura anche in caso di FAIL/INCOMPLETO.

**Affidamento del 7 ottobre 2026.** Il proprietario ha autorizzato la
riattivazione del solo `z3h2njpctmduix`, download, accelerazione e trial
del presente runbook, con sei ore dalla riattivazione e almeno 30 minuti
di chiusura, arresto API a carico dell'agent e nessuna proroga. Codice ed
evidenze pubblicabili vanno su un nuovo branch
`runpod/z3h2njpctmduix/c71-calibration-<data>` via Git HTTPS. La preparazione
locale precede la riattivazione; la nuova deadline va registrata all'avvio.
Verificati localmente i dieci manifest storici e 304 file censiti:
106.904.206 B totali, entro il tetto cumulativo di 10.000.000.000 B.

Il proprietario ha poi attivato manualmente `wgteo4z5mndiof` e fornito
il nuovo endpoint SSH: questo è il solo pod della campagna corrente.
H100 `GPU-1bca9a1c-3fba-8ea6-75a2-c5e656c6a6cd`, stesso modello CPU
Xeon 8480+, `/workspace` inizialmente vuoto su overlay. Il primo uptime
provider implica avvio alle 11:05:46 UTC; si applica prudenzialmente
11:04:46 UTC: fine trial 16:34:46, guard stop 16:59:46, termine massimo
17:04:46 UTC del 7 ottobre. Il guard locale API è attivo; l'arresto finale
va comunque verificato. Nessun credito numerico deriva dall'avvio.
Il proprietario ha inoltre consentito la rimozione del solo cap AS per
i processi CUDA: limiti fisici, pod unico e deadline restano invariati.
Il cap CPU resta 64 GiB. I fallimenti CUDA sotto AS 2 GiB sono conservati;
la parità sul pod è poi passata anche entro AS 64 GiB. I 2 GiB dei
controlli locali non costituivano il cap della calibrazione RunPod.

[c71_campaign_measure.py](../../scripts/c71_campaign_measure.py) riusa
il monitor corretto del bundle storico con deadline e UUID obbligatori
da `AUTHORIZED_END_EPOCH` e `CUDA_VISIBLE_DEVICES`, senza costanti di
sessioni precedenti. Il self-check copre RSS e kill dei gruppi nella
sessione; le misure campionate restano un limite inferiore del picco.
[c71_download_weights.py](../../scripts/c71_download_weights.py) usa
`SHARDS` come directory nuova e conserva l'hash completo degli shard pinned.
Entrambi i programmi arrivano sul pod esclusivamente tramite Git HTTPS.

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
autorizzazione della nuova sessione, sempre da O=0 e senza riuso delle
correlazioni o di stato terminale. Non riavviare il run fallito; un nuovo
trial ha file e journal nuovi. Nessuna proroga o fallback è inclusa.

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
Compilare localmente se il toolkit è disponibile, altrimenti sul pod;
eseguire sulla H100 autorizzata e ripetere la parità alla nuova sessione:

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
CPU ridotti. Impostare binario e `LIBRARY` a build verificate e compatibili
con le sorgenti numeriche correnti, registrando la SHA di ciascuna build;
le sole modifiche documentali non impongono ricompilazione. Eseguire:

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
di un eventuale pod autorizzato. Il harness permette ispezione e chiusura;
non ha un comando di riattivazione. L'agent può usare le API RunPod
`podResume`/`podStop` per il pod autorizzato e rileggere stato, hardware
ed endpoint dopo la riattivazione: UUID, IP e porta precedenti non sono
garantiti. La [documentazione API](https://docs.runpod.io/sdks/graphql/manage-pods)
descrive queste operazioni. Registrare l'istante di riattivazione e
attivare il nuovo controllo di deadline, senza spostare l'inizio al primo SSH.
Il messaggio storico `HARD STOP` nell'help del harness riguarda la creazione
di pod a pagamento senza controllo della durata; non impone un gate
economico aggiuntivo alla riattivazione esplicitamente autorizzata con
deadline e arresto verificabile. Non sono impliciti proroghe o una seconda
macchina. Prima di compilare o generare
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
mentre un volume persistente sopravvive allo stop. Nel checkpoint precedente
`volumeInGb:0` e `/workspace` sul filesystem overlay non davano persistenza
ai pesi. Verificare i mount effettivi; non dedurre persistenza dal solo nome
`/workspace`. `delete` è distinto dall'arresto, distrugge i dati del volume
locale e non è incluso nella sola autorizzazione di riattivazione/arresto.
I tipi di storage sono descritti nelle
[specifiche RunPod](https://docs.runpod.io/pods/storage/types).
Pesi e grandi artefatti non vanno in Git. Pubblicare codice ed evidenze
piccole solo se autorizzati, su un branch unico come
`runpod/POD_ID/c71-calibration-DATE`, senza force-push.

## Campagna di calibrazione

Ogni trial valuta una sola candidata Γ. Registrare SHA pulita,
immagine/container con digest, hardware e limiti autorizzati. Una revisione
delle scale richiede un nuovo trial da O=0 con tutti i controlli. I trial
successivi dipendono dall'autorizzazione della nuova sessione, non dal
record del 4 ottobre. Il completamento dei test non deroga al termine massimo.

I programmi includono pilot NumPy/BLAS CPU o cuBLAS FP64 H100, replay
intero Rust CPU o matrici CUDA esplicite e driver indipendente Python/C11.
La disponibilità dei backend non costituisce una calibrazione completa.
Il pilot supporta `--matrix-workers` (1–20, default 1): i blocchi da 128
righe sono indipendenti, letture e contatori sono sincronizzati, gli
output sono consumati nello stesso ordine e KV resta seriale e causale.
Registrare il numero di worker, mantenere BLAS/OMP a un thread e misurare
insieme i blocchi vivi: otto worker hanno payload W massimo dichiarato
220.200.960 B, oltre al resto del pilot. La parità seriale/parallela va
verificata sul pod prima del nuovo trial; non è accelerazione CUDA né
ammissione di Γ. La scelta è motivata dal throughput del primo pilot
seriale sui pesi reali, incompatibile con il suo timeout.
Il packed regolare è ora mappato in sola lettura, senza una copia W
dequantizzata completa; i buffer in memoria delle fixture restano streamed.
Registrare la mappa W immutabile da 61.394.690.560 B separatamente da
scratch e KV: RSS totale include le pagine W residenti e non è l'arena.
Il limite AS CPU di 64 GiB e gli stop su RSS aggregato/swap restano invariati;
la sola eccezione CUDA è quella esplicitamente concessa dall’owner.
Un host CPU separato non è incluso nell'affidamento dello stesso pod.
Inferenza BF16, TF32 o Transformers non sostituisce la relazione intera.

Il tempo completo non è misurato. L'inizializzatore conta
13.390.420.377.600 prodotti di matrice e 26.782.043.904.000 B di letture W
logiche, che non sono traffico fisico o tempi H100. Alla deadline si
conserva il fallimento e si termina, senza dichiarare Γ calibrato.
L'ammissione di Γ richiede tutti i controlli della
[validazione](#validazione-e-congelamento-del-profilo), incluso il confronto
indipendente; tempo e risorse del confronto rientrano nella campagna.

### Accelerazione dell'inizializzatore

Il prossimo trial risolve il timeout osservato, anziché ripetere il pilot
invariato. Prima del run completo misurare tempi per operatore e token,
conversioni W, lavoro completato, trasferimenti e memoria simultanea.
Registrare backend, worker e librerie; confrontare configurazioni su input
e lavoro identici. Un microbenchmark sintetico non è una previsione del
tempo completo: esplicitare extrapolazioni e quota di lavoro non misurata.
Per il pilot FP64 H100 compilare `cuda/c71_pilot_f64.cu` con `nvcc -O3
-std=c++17 -arch=sm_90 --shared -Xcompiler -fPIC --cudart static -lcublas`.
Eseguire prima la fixture `test_cuda_pilot_fp64_causal_and_ragged_parity`
con `C71_PILOT_CUDA_LIBRARY` esplicita, poi il prefisso reale con
`--cuda-library ... --compare-cuda-matrices`, infine lo stesso prefisso
senza confronto per il timing. Registrare digest, cuBLAS, scale/token e
scarti FP64 privati; la parità numerica non va chiamata bitwise se differisce.
Il report del 4 ottobre non conserva token/operatore raggiunti al timeout;
quei dati non possono essere ricostruiti dai soli campioni RSS.
Per confrontare prefissi identici usare il modo `profile --profile-tokens N`
con gli stessi altri argomenti di `run`, in directory nuove. Il profilo
finisce dopo aver assorbito N token; non produce candidata e non ammette Γ.

Ottimizzare il costo dominante su CPU o H100, verificando il percorso
modificato contro il riferimento numerico su input fissati: valori,
scale risultanti, ordine causale e rifiuti. Conservare il riferimento
necessario a questi confronti e l'indipendenza del driver intero.
Non sostituire la relazione intera con inferenza BF16/TF32/Transformers.
La parità del pilot non concede ammissione di Γ né credito alla prova.
Prima del trial lungo documentare il miglioramento misurato e il piano
di tempo per inizializzazione, tabelle, entrambi i replay, confronto
indipendente, diagnostica e chiusura, entro la stessa deadline.

La telemetria locale salva contesto, indice del token e operatore dello
schedule pubblico, tempi e contatori anche su errore/timeout, in file
nuovi con permessi privati; non salva W/A/KV o intermedi nei log pubblici.
Non inviare avanzamento o ragioni private di arresto al verificatore e
non aggiungere messaggi al transcript. I report pubblicati contengono
solo la selezione revisionata secondo [security](security.md).

### Risorse

| Risorsa | Richiesta proposta / controllo prima del download |
|---|---|
| Compute | 1 H100 SXM 80 GB, almeno 20 vCPU e 125 GB RAM host; verificare l'offerta effettiva |
| Software | Linux x86_64, Python ≥3.11, NumPy, pytest, Rust/Cargo, C/C++ build tools, Git, GNU timeout/time; versioni e immagine registrate |
| Disco | Verificare filesystem, mount e capacità effettivi; almeno 180 GB liberi prima di un download completo, spazio per shard/packed/traccia e ≥20 GB di riserva. La proposta storica 300 GB volume + 40 GB container non è un gate per il pod esistente |
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

Il replay matriciale CUDA del primo trial del 7 ottobre termina per
limite nativo di 1.080 s (wall 1.173,79 s, cap esterno 1.200 s): preservare il FAIL, senza ammissione Γ o riuso
KV. La lettura intera per coefficiente dell'attenzione CPU resta costosa.
Il percorso offline successivo usa righe KV i16 già validate, sommando
QK/PV nello stesso ordine per output; non crea una nuova copia KV.
`c71_calibration profile-attention` confronta esattamente le due geometrie,
O=0/150/300 e query 0/149 col produttore originale, con rifiuti di query
future/padding, marker KV e workspace. Eseguire prima del nuovo trial,
sul pod entro 60 s/2 GiB. Lo screen è sintetico e non ammette Γ.
Il wrapper conserva stderr nativo in un file esclusivo `OUTPUT.native.stderr`,
consultabile durante il replay e conservato anche dopo il timeout.

### Budget delle fasi

Piano del 7 ottobre, fissato prima del pilot completo: pilot FP64 15–20 min,
tabelle/check/hash 5–10 min, due replay CUDA 10–20 min ciascuno, confronto
indipendente 90–110 min, ledger/congelamento circa 5 min. Lo screen CUDA
su W reale e input sintetico coincide esattamente coi due riferimenti CPU:
0,00267 s per 115.605.504 prodotti, oltre a 113,49 s di caricamento W.
Il solo costo matriciale extrapolato è circa 309 s per replay CUDA;
operatori residui, cattura traccia, tabelle e I/O restano stime.
Il confronto C11 extrapolato costa circa 90 min solo per le matrici.
Queste stime non garantiscono il completamento: limite esterno pilot
1.200 s, primo replay/confronto fino a 7.800 s, secondo replay fino a
1.200 s, ridotti se necessario per lo stop computazionale 16:34:46 UTC.
Tabelle separate fino a 600 s e ledger fino a 300 s. I timeout comprendono
hash e preparazione; non si sommano oltre il tempo residuo. Eventuale
O=0/150/300 solo dopo tutti i controlli Γ e con budget residuo esplicito;
nessuna proroga della riserva finale di almeno 30 minuti.
Dopo gli screen esatti a 1/2/4/8 worker si sceglie 8 per il driver C11:
35,5 min estrapolati per le sole matrici, stima completa 50–75 min.
Il replay nativo senza traccia viene eseguito per primo, per rilevare
subito gli overflow; poi replay con traccia e confronto, timeout esterno
fino a 6.600 s, sempre entro lo stop computazionale concordato.


Per stimare il costo del replay prima di disporre della candidata,
`c71_calibration profile-matrix PACKED` misura una proiezione con K massimo
su W reale e input i16 sintetico alternato agli estremi. Eseguire solo sul
pod autorizzato, entro 60 s/2 GiB, con packed già verificato dall'ingest.
Confronta kernel scalare e lettura/dot a blocchi del replay CPU, con tempi
separati e uguaglianza esatta, e dichiara `credit:false`,
`packed_hash_checked:false`, `complete_integer_trial:false`: non valida
scale, tabelle, causalità o Γ. L'extrapolazione dei prodotti è una stima
parziale; aggiungere tabelle, altri operatori, I/O traccia e driver indipendente.
Lo [screen del driver indipendente](../../scripts/c71_profile_oracle_matrix.py)
usa la stessa shape e il kernel indipendente C11, confrontabile col
precedente BLAS con `--compare-reference`; richiede
`NATIVE PACKED`, un solo thread BLAS e AS 64 GiB per il mapping readonly W.
Non istanzia un'esecuzione indipendente completa e non genera frame. Lo screen
accetta `--workers 1..20`: il kernel C11 usa OpenMP solo per righe
indipendenti, con somme i64 immutate e riduzione OR dei marker. Prima di
scegliere `trace --oracle-workers N`, misurare lo screen con confronto
esatto e ripetere `tests/test_c71_calibration_oracle.py` sul pod con
`C71_ORACLE_TEST_WORKERS=N`; i test locali restano a un worker.
Registrare compilatore/runtime OpenMP, numero worker e memoria fisica.
Il driver emette su stderr contesto, token completati, prodotti, frame e
tempo trascorso; non emette valori intermedi privati.
BLAS/OMP/Rayon restano a un thread; il solo dot C11 riceve esplicitamente N.

`profile-matrix PACKED CUDA_LIBRARY` aggiunge il confronto esatto col
kernel intero H100 e include caricamento/installazione W nei contatori.
È uno screen GPU autorizzato, entro 300 s e limiti fisici consueti;
l'eccezione AS concessa vale solo per i processi CUDA. Per un replay con
`--matrix-library`, avviare il wrapper CPU con `ulimit -S -v 67108864`
e hard limit AS illimitato: il wrapper rimuove il soft cap soltanto nel
figlio CUDA, mentre il confronto indipendente resta sotto 64 GiB.

Registrare il nuovo termine autorizzato in `AUTHORIZED_END_EPOCH`, entro
6 ore dalla riattivazione. Non riusare epoch, UUID o guard della campagna
precedente: riconfigurare copie nuove dei monitor e verificarne l'arresto.
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

### Comandi per un trial autorizzato

Build mirata, download e ingestione nativa hanno evidenze PASS sui pesi
reali; pilot completo, tabelle/replay e ammissione restano aperti.
Gli snippet documentano il riferimento CPU; il pilot salva ora avanzamento
privato e tempi per operatore e offre il backend FP64 H100 descritto sopra. Prima
fissare `APPROVED_SHA`, `AUTHORIZED_END_EPOCH`, `TRACE_STEP_SECONDS` e
`NATIVE_TRACE_TIMEOUT_SECONDS`. Usare il pod autorizzato e una delle
alternative Git HTTPS della
[procedura di gestione](#gestione-del-pod-e-del-repository). Il clone e i
percorsi weights seguenti assumono un ambiente nuovo: con file esistenti
applicare prima il riuso verificato, senza sovrascrivere checkout o run.

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

Prima verificare file esistenti e input del bundle secondo il
[riuso](#riuso-del-bundle). Download anonimo ove consentito; l'eventuale
Secret è letto solo in memoria. Ogni tentativo usa file nuovi, senza
ripresa automatica di partial; un nuovo trial preautorizzato non sovrascrive
il fallimento precedente.

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
lettura di verifica. Le tabelle possono essere rigenerate dai digest e
ricette; i dump privati restano sul pod e non entrano in Git o nel bundle
esterno della campagna limitato a 10 GB.

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

### Riuso del bundle

Per riusare il bundle in una nuova campagna, verificarne manifest e hash
dalla destinazione persistente e confrontare modello/packed, workload,
Γ, tabelle e ricette con le identità validate. Registrare il record di
provenienza: si possono saltare le fasi numeriche già validate se codice
e ambiente pertinenti sono invariati, oppure dopo una verifica documentata
dell'impatto delle differenze. Un bundle parziale conserva solo il credito
delle fasi completate. Il bundle del 4 ottobre conserva identità ed
esponenti W, ma nessuna candidata o Γ ammesso. Trasferire solo ciò che
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
eseguito deve essere pulita. L'istruzione del proprietario autorizza i trial
della nuova sessione entro la sua deadline; i record storici non la sostituiscono.
aggiornare i cinque documenti correnti solo quando cambia un fatto,
collegando la nuova evidenza senza sovrascrivere quella precedente.
