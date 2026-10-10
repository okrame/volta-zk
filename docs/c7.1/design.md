# C7.1 — design

[Specifiche](specs.md) · [Sicurezza](security.md) · [Test locali](local-tests.md) ·
[Test su RunPod](runpod-tests.md) · [Archivio](../c7.1-history/README.md)

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

I consumer PCS iniziale, residual e closure lineare limitano gli span
al prefisso `initialized`, rifiutando coda non scritta, overflow e contatori
oltre capacità. Il driver deve descrivere un prefisso contiguo scritto
prima della lettura. Nessun lemma Lean raffina questo contatore C++:
è una premessa implementativa esplicita, sostenuta dalla
[regressione prima/dopo](../c7.1-history/h100-prefix-candidate-2026-10-10.md)
e dalla [parità H100](../c7.1-history/h100-prefix-validation-2026-10-10.md).
Valori, ordine, copertura originale, NoPeek e MAC restano invariati.

La [chiusura locale del 10 ottobre](../c7.1-history/local-exploration-close-2026-10-10.md) registra le esplorazioni successive alla campagna:
verifica degli artefatti conservati, riuso di un solo flag numerico sincrono
(256 B device trattenuti e 8 B aggiunti all'owner host) e quattro screening
di scale A alternative. Il flag viene azzerato prima di ogni operazione;
kernel, letture di stato, fence necessari e controlli restano invariati.
La parità CUDA ridotta delle tre librerie passa nel nuovo preflight;
guadagno sui caller reali e sufficienza dell'allowance restano da misurare. Il conto del setup AES
reale include anche cache W e owner già installati.

Γ ammesso resta il riferimento. Gli screening mantengono W, architettura,
workload e ricette numeriche, ma cambiano la relazione tramite le scale A:
non ereditano ammissione o credito prestazionale. Geometria A/PCS e 512
ricostruzioni iniziali restano invariate. Il [piano hardware mirato](../c7.1-history/local-hardware-plan-2026-10-10.md) distingue costo
API/kernel, attribuzione dello spike e validazione numerica/qualità.
La nuova autorizzazione hardware sopra sostituisce il vincolo di solo
lavoro locale. Trial e correzioni sono coperti entro lo stesso pod,
ambito e deadline; altro hardware o durata restano esclusi.

Il confronto ridotto prima/dopo misura 32→1 allocazioni del flag, con
stessi 32 kernel, 96 fence e 2.176 B D2H inclusa l'osservazione dei raw.
Il census del caller predice 1.185.769 coppie alloc/free in meno per
inferenza e 6.997.504 nei 512 replay A, senza attribuire guadagni di tempo.
Il nuovo massimo nominato sul Γ ammesso è **5.878.735.106 B**, con
**26.844.926 B** residui: il pool è contato anche inattivo e il setup AES
include lo stato W già installato. Allowance e picco fisico restano aperti.

La prima candidata Γ per una futura validazione è il bucket RMS al pari
più grossolano: 159→91 programmi, −13,9216% di prodotti Fp3 del core
RMS/GKR per risposta O=0 e −43,0563% dei byte posseduti dai soli circuiti.
Il bucket al pari più fine dà −14,4015%, ma la requantizzazione delle
attivazioni ammesse espone rischi i16 in 16/5/2 fonti O=0/150/300.
Entrambe compilano nei tre contesti; profondità 99, celle vive, callback,
checkpoint PYS e geometria PCS restano invariati. Le due variazioni dei
soli output hanno beneficio trascurabile o costo maggiore e sono scartate
come ottimizzazioni. Il possesso dei circuiti non è il picco composto:
Builder, packed replay, allocator e workspace richiedono nuovi bound.
Tutte le candidate restano screening non ammessi; margini, errore numerico,
qualità/token, due replay interi e confronto indipendente restano da validare.

Il [seguito locale](../c7.1-history/local-followup-2026-10-10.md) aggiunge il
fill dello zero pubblico score/Z: 7→0 lanci applicativi nella fixture
identica, senza cambiare raw, controlli, fence, allocazioni o lifetime.
Il census predice 3.840 lanci evitati per scan A completa, 1.966.080 nei
512 replay; non riguarda inferenza né lavoro interno CUDA del memset.
La traccia owner è una build diagnostica esplicita, bounded 16 MiB,
owner 42.128 B (32 B aggiuntivi), con clock comune a journal/monitor e
cleanup fail-closed. Il [preflight della nuova H100](../../benchmarks/results/c71-h100-followup-preflight-2026-10-10-7b0885ad316f.json)
verifica packed/esponenti identici e parità CUDA delle tre librerie. La
traccia completa esaurisce 16 MiB in 2,47 s del primo gruppo, senza
completarlo. La build esplicita `C71_OWNER_TRACE_LARGE_ONLY` omette fence
e alloc/free sotto 1 MiB, conserva gli snapshot e lo stesso cap; richiede
la timeline CUDA esterna per gli eventi omessi. Copertura dello spike e
costo fisico restano aperti. Default e ledger restano quelli sopra.

Passano anche predicato RMS originale, replay packed e supporti GKR su
fixture ridotte pesata/non pesata. Lo screen dai metadati conservati dà
upper packed 325.906.729/191.732.984/193.965.966 B per riferimento/coarser/
finer, compreso fixed storico: differenze fra upper, non memoria risparmiata
misurata. Circuiti e PYS coesistono; altro stato del caller/PCG e picco
dei due ruoli restano esclusi. Nessun nuovo bound completo o ammissione.
Il seguito precisa le quattro domande hardware e gli stop, senza eseguirli.

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
componenti ridotti. Il [commitment W completo più recente](../c7.1-history/h100-setup06-checkpoint-2026-10-10.md)
termina in 190,425 s; risposta canonica e picco fisico completo restano aperti. Gli ingressi di test e il lancio
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
| Accumulo W Tensor Core | Limb16 esatto selezionato dopo parità CUDA: 5,663× sul componente W da 256 MiB; stesso owner e capacità globali; PCS W completa più recente in 190,425 s |
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
relazione numerica; la ricerca di un altro Γ resta un lavoro distinto dalla campagna conclusa.
La baseline della campagna è `c7e05cf`, che include `24b54d4`.
I [sei trial](runpod-tests.md#stato-e-sequenza-operativa) mantengono Γ,
semantica, MAC originali, correlazioni monouso e PCG AES. Ogni nuovo trial
riparte da W e KV vuoto, senza importare una sessione terminale.
Il [setup completo aggiornato](../c7.1-history/h100-setup06-checkpoint-2026-10-10.md)
risparmia 492,620 s (1,330× osservato) rispetto al precedente; i due ruoli
lavorano simultaneamente e i loro tempi non si sommano. Il traffico setup
è invariato a 61.841.366 B. Il microbenchmark cGGM misura 1,475×, senza
attribuirlo automaticamente al setup o alla risposta.

Le configurazioni stack 256 B, pagine grandi consigliate su W e code
compute/copy 1/1 sono validate con parità reale. Nel diagnostico di sola
inferenza il massimo temporaneo scende da 1.474.276.864 a 1.216.531.968 B;
sono scope identici di componente, non picchi canonici completi.
Il batching del prompt esatto rallenta a 132,036 s (+45,71%) ed è
[ritirato](../c7.1-history/h100-prefill-2026-10-09.md). L'inferenza scalare
selezionata misura 84,382 s; il caricamento W varia fra i trial e viene
registrato separatamente, senza attribuirne la variabilità ai kernel.

Lo [stop del sesto trial](../c7.1-history/h100-canonical-06-2026-10-10.md)
lascia aperta l'allowance fisica: il payload è sotto cap ma la memoria
GPU salta di 504 MiB fra gli ultimi due campioni. La causa non è dimostrata.
Il diagnostico con code `0.25x` conserva geometria, cap e monete fresche;
non include la ritenzione W/setup e non fornisce credito canonico.
Il profilo pubblico attribuisce 131.072.000 B transienti al RNE finale;
è un'indicazione analitica, senza nuova schedule selezionata. Il timeout
CPU storico dopo circa 41 minuti resta il fallimento della sua schedule
da 1.024 scansioni, non una misura dell'attuale commitment H100.

Il [passaggio operativo](../c7.1-history/crypto-preh100-operations-2026-10-09.md)
conserva 65 test locali, ingresso CUDA esplicito, timeout diagnostico distinto
dal target 65 s e monitor con cap fisici. La [chiusura](../c7.1-history/h100-campaign-close-2026-10-10.md)
registra spegnimento e limiti residui; nuovo hardware o nuova durata
richiedono nuova autorizzazione. I campioni durante transizioni W non
attribuiscono credito congiunto. Raffinamento Seed6/CUDA, allowance,
picco completo e target della risposta rimangono aperti.

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

Il [conto tipato del 9 ottobre](../../benchmarks/results/c71-preh100-operational-local-2026-10-09-24b54d414421.json) enumerava 653 fasi e le 11
classi di allocazione, compresi cache/workspace RMS e gli 8 B aggiunti
per seguire il lifecycle W: massimo 5.878.734.842 B e 26.845.190 B residui
nel payload di 5.905.580.032 B. La [chiusura locale del 10 ottobre](../c7.1-history/local-exploration-close-2026-10-10.md)
aggiorna il conto con flag trattenuto, nuovo owner e cache W già vive
nel setup AES reale; il massimo storico non è il bound del codice attuale.
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
Il nuovo fill dello zero pubblico assume inoltre la corrispondenza fra
memset ordinato CUDA e output i64 zero, con guardie/flag/fence preservati;
la parità CUDA ridotta passa, senza lemma Lean di raffinamento.
La traccia diagnostica e l'allineamento dei clock sono strumenti di
laboratorio, senza nuovo credito di raffinamento o di picco fisico.

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
