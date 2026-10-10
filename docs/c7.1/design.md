# C7.1 — design

[Specifiche](specs.md) · [Sicurezza](security.md) · [Test locali](local-tests.md) ·
[Test su RunPod](runpod-tests.md) · [Archivio](../c7.1-history/README.md)

La [coda SHAKE cGGM differita](../c7.1-history/h100-cggm-tail-2026-10-09.md)
passa 17 test CPU sul pod e conserva output, scarti e correlazioni monouso.
Il microbenchmark misura 1,475× sul componente; il setup completo con
questa modifica non è misurato e `canonical-05` usa il binario precedente.

`canonical-05` termina con `Stop` nel primo gruppo A dopo preparazione
84,831 s; massimo fisico campionato 6.140.513.792 B, sotto il cap.
La causa privata era persa dal messaggio uniforme. `commitment-a-cuda`
isola preparazione e commitment iniziale A con geometria/limiti originali
e monete fresche, senza setup, W commitment o certificati. Il suo risultato
non sostituisce il percorso canonico; serve a diagnosticare questo stop.

Il [diagnostico A](../c7.1-history/h100-a-diagnostic-2026-10-10.md) riproduce
un rifiuto del tile originale: i consumer PCS/lineari richiedono capacità
interamente scritta, mentre KV contiene un prefisso inizializzato. La
correzione deve limitare gli span a quel prefisso, senza ammettere la coda.

La correzione dei tre consumer usa `initialized` come limite degli span,
come il gather già esistente; capacità, byte originali e ordine restano
immutati. Richiede l'invariante del driver che `initialized` descriva un
prefisso contiguo scritto prima della lettura. Nessun lemma Lean raffina
questo contatore C++; la corrispondenza resta una premessa implementativa
esplicita, con regressione prima/dopo e parità finita, non nuovo credito
al protocollo. Nessuna lettura della coda o modifica dei MAC è ammessa.

## Obiettivo e relazione dimostrata

C7.1 dimostra a un verificatore designato l'inferenza intera di un modello
privato e la continuazione della sua memoria di attenzione, chiamata KV.
Tutte le risposte accettate devono usare gli stessi pesi W fissati
all'installazione. Il verificatore apprende i token pubblici e l'esito;
non riceve pesi, attivazioni o valori intermedi privati.

Il modello è la parte testuale di `google/gemma-4-31B`, con
[identità immutabile](specs.md#input-e-identità). La relazione usa la semantica
intera in [specs](specs.md#semantica-numerica): arrotondamento al più vicino
con pareggi al pari, rifiuto degli overflow e softmax `C71-SOFTMAX-EXP30-v1`.
Il nome `gemma31b` nei percorsi del codice identifica questo checkpoint.
Il commitment certifica i pesi installati; la loro provenienza e la qualità
del modello sono proprietà separate.

Un'esecuzione parte da KV vuoto e comprende al massimo tre tentativi.
Ogni tentativo contiene 100 token di prompt e 50 generati; i contesti
precedenti hanno quindi lunghezza O=0, 150, 300. Si certifica anche KV
dell'ultimo token emesso. Qualsiasi errore, interruzione o esaurimento
termina definitivamente l'esecuzione. Non sono previsti rinnovi,
riavvii, importazione di ricevute o prosecuzione dopo un rifiuto.

## Organizzazione del protocollo

Il parametro pubblico Γ fissa modello, scale, tabelle numeriche, disposizione
dei dati e ricette dei circuiti. Il verificatore lo valida e lo possiede
prima di installare W o predisporre correlazioni crittografiche.
La calibrazione deve riguardare i pesi reali e il workload fissato nei tre
contesti. Non è richiesta una certificazione generale della qualità.

L'installazione di W è indipendente dalla chiave del verificatore e dalla
sessione. Il setup crittografico predispone invece una capacità finita di
correlazioni monouso. Prima di ogni prova, il preparatore calcola e valida
tutti i valori privati senza leggere quelle correlazioni. La prova può
ricostruire valori, purché coincidano esattamente con quelli fissati.

Le verifiche matriciali, numeriche, di intervallo e della storia KV
confluiscono in aperture PCS sui valori autenticati originali. PCS indica
il commitment polinomiale e la sua prova di apertura; un nuovo MAC valido
su un valore diverso non chiude il requisito. Ogni risposta usa una PCS
di W, una per ogni A precedente e una per l'A corrente, dove A raccoglie
tutti gli ausiliari della risposta. Non esistono prove PCS per token.

Un unico transcript Fiat–Shamir determina le sfide della prova a partire
dai messaggi già fissati. Il verificatore ricostruisce contesto e storia
dal proprio registro. Brucia l'intera riserva prima dell'uso e promuove
la nuova A e KV solo dopo tutte le verifiche e la registrazione durevole
dell'accettazione. Un semplice ACK non promuove lo stato.

## Costruzione da implementare

Il percorso di implementazione conserva la relazione e l'ordine di verifica
B12, con W packed immutabile, lettura ordinata di A, ricostruzione per
finestre e PCS senza vettori sorgente completi. La configurazione attuale delle
risorse usa 512 ricostruzioni per il commitment iniziale A, stato S1
trattenuto per A e apertura RS mediante resti di polinomi. I parametri e
gli obblighi di memoria sono in [specs](specs.md#pcs-e-ricostruzione-dei-valori).

Il generatore efficiente di correlazioni è il riferimento CPU Seed6,
abilitato esplicitamente da `c71-seed6-reference`, con la premessa
EA-LPN-SL-reg* autorizzata. Il teorema B12 sul bootstrap originario e
questa estensione hanno confini distinti: [security](security.md) espone
le ipotesi e ciò che resta da dimostrare. L'esecuzione di test Seed6
non trasferisce automaticamente i bound B12 al programma completo.

## Stato di implementazione e lavoro necessario

Il runner esplicito `experiment-cuda` collega i 13 producer, inferenza
causale, replay A, PCS/range/GKR, verifica e promozione per O=0/150/300.
È un percorso misto GPU/CPU. La tabella descrive l'integrazione corrente.
La [campagna H100 del 9 ottobre](../c7.1-history/h100-components-2026-10-09.md)
ha compilato sm_90 e passato i 15 test CUDA reali. I benchmark sono
componenti ridotti. Il [commitment W completo più recente](../c7.1-history/h100-w05-checkpoint-2026-10-09.md)
termina in 190,200 s; risposta canonica e picco fisico completo restano aperti. Gli ingressi di test e il lancio
sorvegliato sono nel
[runbook](runpod-tests.md#preparazione-operativa-della-campagna).

| Parte | Stato e confine |
|---|---|
| Telemetria e XOF | Integrati: fasi e avanzamento durevoli, lavoro/trasferimenti/census, buffering sequenziale da 4 KiB con stream/seek/replay originali |
| Commitment iniziale W | Integrato nel Tree/runner: accumuli esatti, FFT, foglie incrementali e Merkle sul common owner; 32 coset/otto colonne, 128 scansioni analitiche sul pinned |
| Commitment iniziale A | Producer residenti collegati alla PCS, quattro coset/tutte le 128 colonne, istogramma fuso nel primo replay; 512 ricostruzioni conservate, nessun download per riga nel commitment |
| Sali iniziali W/A | Prescan e replay selezionati sullo stream comune, cursore logico e cap originali; niente bande host/upload sali |
| FFT naturale diretta/inversa | Integrata nell'owner, usata dalle query iniziali A e dagli stadi extension PCS |
| Query iniziali A | Reader residente e resti collegati al Tree/runner, con sole valutazioni finali D2H; costruzione dei fattori pubblici CPU, richieste e ricostruzioni originali |
| Query iniziali W | Selezionate nel commitment nativo: packed sigillato e resti sul common owner, senza upload delle finestre W; Horner e catena WHIR D10 esatti |
| Closure lineare | Owner e caller nativi integrati con parità ridotta: una scan originale per round, D·live visite, cinque elementi MAC e flag restituiti; mapping W riusato, nessun getter A sostitutivo |
| PCS S1 e successori | Route canonica collegata a `model.native_original`: singleton, coset/FFT/hash/sali, OOD, retention A dopo apertura del predecessore, fold e contrazioni sul common owner; W continua a leggere il packed originale |
| Query extension A/W | Tre componenti PCS caricate nello stesso passaggio e resti residenti in tutti gli stadi; A legge le plane trattenute, senza ricostruzioni originali aggiunte; sole valutazioni finali D2H |
| Accumulo W Tensor Core | Limb16 esatto selezionato dopo parità CUDA: 5,663× sul componente W da 256 MiB; stesso owner e capacità globali; PCS W completa più recente in 190,200 s |
| QK/PV | Default scalare esatto; candidata MMA con prefisso causale comune e bordo scalare non selezionata |
| RMS misto | Replay Booleano CPU a 64 lane con DAG per depth; primo round esatto e cache compatta delle geometrie pubbliche. Selezione solo senza pattern prefix e con più programmi; coefficienti Fp3 ed endpoint restano CPU |
| Resto della prova | Fattori pubblici, rigenerazione Merkle delle aperture, GKR/MAC, Seed6 reale AES, codec, verifica e journal CPU; tempi completi da misurare |

[canonical_device.rs](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_device.rs)
possiede la sessione numerica: stessa Arc W del commitment, un solo
runtime/stream/arena, tabelle, una generazione di checkpoint/istogrammi
ed una capacità KV per 450 token. Matrix usa quattro MMA INT8 esatte,
Norm soglie u128 e gli altri producer la semantica canonica. Producer e
preparatore non ricevono transcript, monete PCS o correlazioni; le viste
storiche mantengono il prefisso causale. Errori, panic, CUDA assente e
cleanup falliti sono terminali, senza retry o fallback.

I consumer CPU usano staging privato bounded. Range A, query iniziali W/A e query extension sono residenti;
il gather range W usa ancora upload signed per finestre fino a 256 MiB.
Il
[conto tecnico](specs.md#runner-cuda-sperimentale-e-conto-simultaneo)
distingue capacità, trasferimenti e stati simultanei: tetto payload
5.905.580.032 B, più riserva fisica esplicita di 256 MiB, totale
condizionato 6.174.015.488 B e ulteriori 256 MiB di margine. La sufficienza
della riserva e il completamento canonico sono aperti.

La telemetria misura wall annidati, traffico applicativo, census ai
confini delle fasi, ledger cumulativo CUDA e RSS/HWM. Non sommare picchi
separati o contatori cumulativi. Il monitor esterno applica deadline e
arresti fisici campionati. Per l'installazione W sono disponibili campioni
simultanei host/HBM; allowance e picchi completi restano da dimostrare. Non sono acquisiti certificati canonici o misure
D34/D35 complete della prova. La
[parità H100 precedente](../../benchmarks/results/c71-h100-corrected-parity-2026-10-04-d3c2fa95eaf7.json)
riguarda operatori sintetici e MAC originali, non il percorso ottimizzato.

## Risultati attuali e prossime ottimizzazioni

Γ è **ammesso** per modello, byte W, workload, semantica, scale, tabelle
e ricette pinned. Si riusa dopo verifica di identità e impatto delle
modifiche; si ripete la calibrazione solo quando l'ammissione pertinente
è invalidata. È l'unico Γ ammesso finora, non un optimum prestazionale
dimostrato. Cambiare scale può semplificare i circuiti ma cambia la
relazione numerica; la ricerca di un altro Γ è distinta dal goal corrente.
Il [primo W della campagna H100](../c7.1-history/h100-w-setup-2026-10-09.md)
ha completato PCS W in 360,301 s e l'installazione W in 404,340 s,
con 128 scansioni/7,859 TB logici. Il setup Seed6/AES termina in
2.018,838 s; il [primo trial](../c7.1-history/h100-canonical-01-2026-10-09.md)
fallisce durante la preparazione O=0, senza violazioni dei limiti. Il loader
CUDA rifiutava marker di overflow in voci pubbliche non selezionate.
La [correzione validata](../c7.1-history/h100-inference-01-2026-10-09.md)
passa otto regressioni e la parità CUDA 15/15. Il diagnostico O=0
completa l'inferenza in 90,615 s, con tutti i token uguali al replay
intero ammesso, senza prova o promozione KV. Il
[batching del prompt](../c7.1-history/h100-prefill-2026-10-09.md) è esatto
ma rallenta a 132,036 s (+45,71%), nonostante −65,98% lanci: è ritirato.
Il [terzo trial](../c7.1-history/h100-monitor-stack-2026-10-09.md), su binario
scalare `2a31625`, termina dopo 572,209 s per copertura W incompleta in
una lettura smaps, dopo PCS W 436,687 s e prima del completamento del setup.
Il monitor ora conserva e limita le riletture senza allentare il cap fisico.
La [riserva iniziale CUDA di 256 B](../c7.1-history/h100-stack256-2026-10-09.md)
è selezionata dopo 15/15 CUDA e inferenza esatta a 90,594 s. Il massimo
temporaneo campionato scende di 207,229 MB a 1,267 GB, senza credito al
picco completo o a un guadagno di tempo. Il
[quarto trial](../c7.1-history/h100-canonical-04-2026-10-09.md) termina
nel primo gruppo A: temporanee fisiche 6.190.775.808 B, 16.760.320 B
oltre il limite. W e setup sono completi, preparazione O=0 87,349 s;
nessun commitment A o certificato completo. Il payload sotto cap non
basta a dimostrare l'allowance fisica.
Il [probe procfs](../c7.1-history/h100-thp-candidate-2026-10-09.md) misura
0,928 s per una lettura smaps di W su pagine da 4 KiB. La candidata
`920e684` consiglia pagine grandi prima del caricamento. La
[validazione H100](../c7.1-history/h100-thp-validation-2026-10-09.md)
passa 15/15 CUDA e token esatti: inferenza 85,393 s (−5,741% osservato),
caricamento più lento a 153,661 s, temporanee circa invariate. Smaps scende
a 0,025 s nel probe, mediana 0,059 s durante la preparazione. Nessun
credito al picco completo. Le
[code CUDA a una connessione](../c7.1-history/h100-queue1-2026-10-09.md)
passano 15/15 e inferenza esatta a 84,382 s: massimo temporaneo campionato
1.216.531.968 B, −50.434.048 B rispetto alla stessa build con code di default.
Sono selezionate per `canonical-05`, da W alle 23:13:42 UTC con AES/journal
freschi; il picco canonico rimane da verificare.
Il [checkpoint W successivo](../c7.1-history/h100-w05-checkpoint-2026-10-09.md)
misura PCS 190,200 s e installazione 207,973 s (PCS −53,060% rispetto
al trial precedente). Il caricamento sale a 322,159 s: W pronto a
571,376 s, contro 552,786 s. Il [trial concluso](../c7.1-history/h100-canonical-05-2026-10-09.md)
completa setup 1.986,453 s e preparazione 84,831 s, poi termina con `Stop`
nel primo gruppo A. Nessun certificato acquisito.
Il profilo pubblico del replay attribuisce il transiente da 131.072.000 B
al RNE finale; è un'indicazione analitica, senza nuova schedule selezionata.
Γ, causalità, replay e garanzie restano invariati. O=0/150/300 non sono verificati.
Il precedente timeout CPU dopo
circa 41 minuti rimane il fallimento di quella schedule da 1.024 scansioni,
non lo stato del commitment H100 corrente. La CLI ricostruisce W a ogni
avvio e non riprende installazioni o sessioni interrotte.

La candidata cGGM legge 136 byte SHAKE e materializza gli ultimi 56 solo
se il primo candidato del terzo slot è scartato. Frame e tre slot da
64 byte restano identici; cambiano soltanto byte effettivamente estratti
e relativo contatore. Golden, parità col campionatore completo, rifiuti
fino a esaurimento e setup/journal ridotti passano localmente. Non è
usata da `canonical-05`; il microbenchmark H100 misura 1,475×, mentre
il setup completo con questa modifica resta da misurare.
Il raffinamento generale Seed6/CUDA resta aperto come in [security](security.md).

Il goal corrente esegue la campagna H100 autorizzata, entro otto ore
provider e con guard indipendente, secondo il [runbook](runpod-tests.md).
La baseline `c7e05cf` include le correzioni operative `24b54d4`.
Il
[checkpoint locale](../../benchmarks/results/c71-crypto-rms-local-2026-10-09-abd2de09efb4.json)
conserva parità, benchmark e ledger. La successiva revisione del passaggio
alla H100 ha aggiunto ingressi di test espliciti sulla libreria reale,
timeout diagnostico separato dal target di 65 s e lancio sorvegliato.
Il [runbook](runpod-tests.md#preparazione-operativa-della-campagna)
definisce la procedura aggiornata e i suoi limiti: i campioni nelle
transizioni di W non attribuiscono credito congiunto di memoria;
picco completo, allowance e target hardware restano aperti.
La [chiusura operativa locale](../c7.1-history/crypto-preh100-operations-2026-10-09.md)
registra 65 test passati e il ledger aggiornato: codice e procedure sono
pronti alla richiesta di hardware. Nuova H100 e durata richiedono nuova
autorizzazione.

Il [checkpoint S1 e Query E](../c7.1-history/crypto-residual-query-2026-10-09.md)
collega owner e caller fino alle query extension di tutti gli stadi.
Le catene WHIR D10 A/W conservano wire, FS/RNG e MAC originali;
getter e finestre host private sono vietati nelle route residenti.
La schedule S1 non-query è preservata e il commitment iniziale A resta
a 512 ricostruzioni. Il [checkpoint W e profilo residuo](../c7.1-history/crypto-local-convergence-2026-10-09.md)
aggiunge query iniziali W, retirement numerico prima dell'hash A e Writer
canonico di capacità fissa. Il profilo sul Γ ammesso quantifica anche il
grande replay Booleano/GKR RMS CPU, ora aggiornato dal
[checkpoint RMS](../c7.1-history/crypto-rms-close-2026-10-09.md).
Preparare soltanto la PCS non chiude il target della risposta.
Fattori, FFT dispari, range e producer restano costi
separati; almeno 581 scan complete dell'A corrente precedono le richieste
parziali e gli altri consumer.

Il [conto tipato aggiornato](../../benchmarks/results/c71-preh100-operational-local-2026-10-09-24b54d414421.json) enumera 653 fasi e le 11
classi di allocazione, compresi cache/workspace RMS e gli 8 B aggiunti
per seguire il lifecycle W.
Il massimo modellato è 5.878.734.842 B,
con 26.845.190 B residui nel payload di 5.905.580.032 B.
Rimane condizionato alle capacità dei path/argv
≤4.096 B ed alle identità Γ/layout registrate; `joint_admitted:false`
conserva il confine rispetto al picco fisico non misurato.
Il [checkpoint capacità](../c7.1-history/crypto-capacity-close-2026-10-09.md) chiude i bound tipati di profili,
wire/decoder, forme, telemetria, setup AES e compilatore RMS. Preflight
pubblico prima di W/history e compattazione KV preservano byte/FS/MAC;
le batch P/V appartengono a fasi successive, non simultanee.
RMS conserva gli stessi circuiti: `PackedReplay` usa 64 lane ed il DAG
per depth; la cache riduce analiticamente le compilazioni 4.293→1.908.
Il primo round esatto elimina 128.288.785.794.560 moltiplicazioni dal
core coefficienti di 972.294.988.954.860, pari al 13,19443%; rimangono
844.006.203.160.300 moltiplicazioni Fp3 CPU. I 998.927.195.904 callback
del checkpoint per risposta non diminuiscono. Benchmark CPU ridotti con
scale nonzero verificano il replay, senza attribuire tempi al Γ ammesso
o alla H100. La catena AES composta e
un test KV completo rimangono incompleti a 60 s locali; non ereditano
crediti dai componenti positivi. Valutare TMA, fusioni e CUDA Graphs
su costi misurati. Il confronto W ordinario/Tensor sulla H100 giustifica
la selezione Tensor
nel Tree; il [record componenti](../../benchmarks/results/c71-h100-components-2026-10-09-d00d46308029.json)
conserva i campioni esatti e i loro limiti. QK/PV rimane scalare. Il codec cGGM ora
assorbe direttamente lo stesso frame SHAKE, eliminando il buffer heap
per nodo; [parità e benchmark](../c7.1-history/h100-w-setup-2026-10-09.md)
non dimostrano un guadagno temporale. Il primo trial canonico usa
il codec precedente; non attribuire alla modifica i suoi tempi.

Le geometrie fisiche W CUDA 32 coset/otto colonne, CPU W quattro coset
ed A quattro coset sono modificabili con equivalenza esatta e nuovo
conto di scansioni/ricostruzioni, memoria e capacità simultanee. Non
trasferire implicitamente il blocco di colonne W ad A. Sali/pad/root,
ordine naturale, transcript, NoPeek e MAC originali devono rimanere
invariati. Le geometrie escluse restano escluse per le loro premesse;
riaprirle richiede risolvere e verificare la causa.

Gli obblighi prestazionali già quantificati restano visibili: A iniziale
512 ricostruzioni; sali prescan/replay almeno 274.877.906.944 B XOF W e
137.438.953.472 B A per risposta, anche dopo eliminazione degli upload
sali; D15 W/A non cached e un test CPU lookup/GKR/WHIR superano 60 s
locali. Anche i test RMS c0 reale e mixed421 con PCS conservano timeout
a 60 s; non estenderli o trasferire loro il credito delle fixture ridotte.
Cache di riferimento da 16 MiB solo nelle fixture composte non risolvono
tali timeout in produzione. Il ledger conclusivo sostituisce gli screen
parziali; il picco fisico completo rimane da verificare.

**Premesse residue.** I lemmi Lean richiamati in [security](security.md)
non raffinano implementazione CUDA, scheduling, gather, immutabilità
fisica o composizione Seed6. Il replay assume determinismo dei kernel
corretti su W/tabelle sigillati, token fissati e prefissi KV originali;
controlla token rigenerati e copertura, senza un digest privato di tutta
A confrontato a ogni replay. PCS usa v³=v+1, MAC u³=2; gli endpoint
rimangono VOLE-autenticati sugli originali. Test finiti, anche sulla H100
reale, e compilazione sm_90 non scaricano
queste premesse. La selezione W limb16 assume inoltre la corrispondenza
esatta delle istruzioni MMA/shuffle e della ricomposizione intera verificata
su fixture; nessun lemma Lean la raffina.

### Evidenze e decisioni

Questa è la mappa dei checkpoint, ciascuno riferito alla propria SHA;
le lacune storiche in tabella non sostituiscono lo stato corrente sopra.
Dettagli di fixture, RSS, tempi, fallimenti e provenienza rimangono nei
record e nelle storie datate.
Ogni nuova integrazione deve avere parità esatta ridotta, benchmark
rappresentativo e conto completo prima della selezione. Le evidenze
locali sono `credit:false`, senza compilazione o esecuzione CUDA.

| Evidenza | Ambito e limite |
|---|---|
| [Ammissione Γ](../../benchmarks/results/c71-gamma-admission-2026-10-07-868a3e8.json) | Due replay interi e confronto indipendente completo sul workload pinned; non certificati canonici |
| [Diagnostica canonica](../../benchmarks/results/c71-cuda-experiment-2026-10-07-868a3e8.json) | Timeout iniziale W, prima delle risposte; [cronaca](../c7.1-history/design-2026-10-07.md) e [runbook datato](../c7.1-history/runpod-tests-2026-10-07.md) conservano risorse campionate e chiusura |
| [Telemetria/XOF](../c7.1-history/crypto-preparation-2026-10-08.md) | Stream/seek/cap, JSONL durevole e positivo Seed6/AES ridotto |
| [Hash W](../c7.1-history/crypto-w-hash-2026-10-08.md), [accumuli/FFT W](../c7.1-history/crypto-w-scan-fft-2026-10-08.md), [Tree W](../c7.1-history/crypto-w-tree-2026-10-08.md) | Incremental hash, valori/campi, root/aperture, transcript/MAC; timeout uncached conservato |
| [Consumer A](../c7.1-history/crypto-a-source-2026-10-08.md), [Tree A](../c7.1-history/crypto-a-tree-2026-10-08.md) | Codec originale, producer→PCS, istogramma, root/aperture e prova composta; timeout uncached conservato |
| [Closure/XOF/confronto Tensor](../c7.1-history/crypto-components-2026-10-09.md) | Componenti esatti e confronto owner; [correzione causale QK/PV](../../benchmarks/results/c71-attention-causal-local-2026-10-09-29a257b4476b.json) distinta dal finding iniziale |
| [Sali owner/Tree](../c7.1-history/crypto-salts-owner-2026-10-09.md) | Stream privato, root/aperture/transcript/MAC e conto aggiornato; gerarchia CUDA non eseguita, timeout CPU conservato |
| [FFT naturale owner](../c7.1-history/crypto-transform-2026-10-09.md) | Diretta/inversa esatte, geometria dispari e guard; primitiva integrata, query caller ancora CPU al source validato |
| [Query iniziali A residenti](../c7.1-history/crypto-query-2026-10-09.md) | Horner, richieste identiche e catena D10 uncached con wire/FS/RNG/MAC originali; extension/S1 e caller lineare ancora CPU |
| [Closure lineare owner/caller](../c7.1-history/crypto-linear-2026-10-09.md) | Codec e coefficienti/endpoints originali, consumo monouso, full wire D10; S1 aritmetico distinto, nessuna parità CUDA |
| [Lifetime PCS e hash extension paired](../c7.1-history/crypto-retirement-short-merkle-2026-10-09.md) | Rilascio batch/prove, BLAKE3 pinned e regressione sali; hash S1 non selezionato, timeout composto conservato |
| [S1 e query extension sul common owner](../c7.1-history/crypto-residual-query-2026-10-09.md) | Route canonica, parità WHIR D10 A/W e guard privati; query iniziali W ancora CPU, conto nominato non ammesso, nessuna compilazione/esecuzione CUDA |
| [Query W, profilo del caller e audit di convergenza](../c7.1-history/crypto-local-convergence-2026-10-09.md) | 14 filtri Rust e tre test Python passano; RMS sul Γ ammesso quantificato parzialmente, timeout della catena AES conservato, quattro classi di capacità aperte |
| [Capacità tipate e preflight originali](../c7.1-history/crypto-capacity-close-2026-10-09.md) | Parità lineare D10 esatta; 653 fasi con bound condizionati, picco fisico e accelerazione RMS ancora aperti |
| [Replay e geometrie RMS](../c7.1-history/crypto-rms-close-2026-10-09.md) | Replay64 su scale nonzero, parità dei conteggi e primo round esatto; fixture GKR completa senza PCS con wire/FS/RNG/MAC, nessun tempo H100 |
| [Chiusura operativa pre-H100](../c7.1-history/crypto-preh100-operations-2026-10-09.md) | 65 test locali, 15 ingressi hardware registrati, trasporto/monitor corretti e ledger aggiornato; nessuna esecuzione CUDA |
| [Regole operative](../c7.1-history/operating-rules-2026-10-08.md), [temporanei](../c7.1-history/temporary-memory-2026-10-04.md) | Ragioni delle decisioni; autorizzazioni correnti definite nel [runbook](runpod-tests.md#autorizzazione-e-limiti) |

## Contratto delle risorse

| Quantità | Requisito |
|---|---:|
| Tempo completo per risposta sulla singola H100 | ≤65 s |
| Certificato completo iniziale, setup di sessione incluso | ≤130.000.000 byte |
| Certificato completo di ogni continuazione | ≤40.000.000 byte |
| Memoria globale H100 | <80.000.000.000 byte, con almeno 1 GiB libero nel piano |
| Arena per tutti i temporanei dell'implementazione | 6.442.450.944 byte, con almeno 256 MiB liberi |
| W packed | 61.394.690.560 byte |

Il codec B12 corrente supera analiticamente 40 MB nelle continuazioni.
La [composizione H100](../c7.1-history/h100-monitor-stack-2026-10-09.md)
del prefisso realmente scambiato e del corpo minimo analitico porta il
primo turno ad almeno 134.174.406 B nei due sensi, distribuzione pubblica
inclusa: supera 130 MB. Non è una dimensione di certificato misurato.
Il ripiego analitico autorizzato è 47,84 / 54,87 / 61,80 MB per
O=0/150/300: sono i limiti inferiori del corpo in
[specs](specs.md#ordine-e-formato-del-certificato), non dimensioni misurate,
limiti superiori o nuovi cap dei certificati. È ammesso concludere così
la valutazione negativa del requisito 40 MB; questa disposizione non
allenta tempo, memoria o sicurezza.

Si conta tutto il lavoro: generazione, ricostruzione del testimone, PCG,
prova, serializzazione e trasferimenti necessari. Il lavoro totale su
ogni prefisso deve essere non crescente rispetto alla baseline a parità
di modello, semantica, token e sicurezza. Caricamento globale e setup di
sessione hanno voci distinte; non vi si nasconde lavoro della risposta.
Memoria aggiuntiva esterna può contenere solo materiale globale del modello,
riutilizzabile senza crescita con le sessioni. Nessuno spill dinamico.
Quattro letture W sono un obiettivo di ottimizzazione, non un limite rigido.

Il budget comune comprende PCS, GKR, Seed6, staging, prove, entrambi i
ruoli e tutte le capacità Rust trattenute, oltre ai buffer CUDA allineati.
Si esclude soltanto il payload W packed immutabile. Le allocazioni grandi
host usano una soglia glibc mmap fissa, evitando che i workspace liberati
rimangano nei successivi picchi come grandi cache dell'allocatore.
Il [conto corrente](specs.md#runner-cuda-sperimentale-e-conto-simultaneo)
separa limite imposto, subtotal derivati dalle shape, test ridotti e
riserva fisica. Il [checkpoint locale](../c7.1-history/temporary-memory-2026-10-04.md)
conserva decisioni, limiti e fallimenti. Nessuna riclassificazione dello scratch della risposta.

I gruppi CPU mantengono 512 scan iniziali A e 1.024 W, ma eseguono
quattro accumulazioni di campo per coefficiente iniziale (due per S1/S2),
con FFT più piccole. Il lavoro extra è della prova: non eredita i tempi
analitici precedenti e non dà credito al requisito di lavoro non crescente.
Restano invariati protocollo, transcript, monete e MAC; non è introdotto
un lemma Lean di raffinamento dell'allocatore o dei kernel. Le assunzioni
numeriche/formali già aperte restano quelle della sezione sicurezza.

## Uso dei documenti

Questi cinque file costituiscono la documentazione operativa. `design.md`
definisce obiettivo e scelte; `specs.md` descrive algoritmi, dati e codice;
`security.md` contiene enunciato, dimostrazione e obblighi residui;
`local-tests.md` e `runpod-tests.md` definiscono verifiche e procedure.
Le [decisioni ed evidenze storiche](../c7.1-history/README.md) conservano
provenienza e fallimenti, senza fornire istruzioni operative concorrenti.
