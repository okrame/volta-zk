# C7.1 — misure discriminanti dopo la campagna H100

Piano locale del 10 ottobre; **nessuna esecuzione hardware autorizzata o
avviata**. Stato operativo nei [test RunPod](../c7.1/runpod-tests.md).
La [chiusura H100](h100-campaign-close-2026-10-10.md) resta la baseline
misurata: zero certificati, inferenza intera esatta 84,382 s, prova e
verifica complete mancanti. Prima di qualsiasi campagna occorrono nuova
autorizzazione di hardware/durata, build compatibili e parità reale.

## 1. Da dove arrivano i 504/509 MiB dello spike A?

**Baseline/input.** Γ ammesso, W verificata e sigillata, geometria A D34,
quattro coset e 512 ricostruzioni, stack 256 B, code 1/1. Ripetere prima
un componente strumentato, poi il tratto canonico con W commitment e setup
effettivamente trattenuti. Ogni invocazione usa monete/journal nuovi.
A06 e A04 sono due baseline differenti: A04 omette W/setup; il suo maggior
numero di gruppi non dimostra migliore memoria. Il nuovo flag trattenuto
deve essere contato anche quando inattivo.

**Misura.** Correlare monotonic timestamp, fase/gruppo e chiamante pubblico
con ogni prenotazione owner: ID/handle, kind, byte richiesti/allineati,
alloc/free tentata e completata, live capacity prima/dopo, esito. Registrare
gli eventi CUDA runtime/driver, launch e completamento kernel, memcpy,
memset e fence; associare il kernel alla sua API mediante correlation ID.
Affiancare `cudaMemGetInfo`, HBM dell'intero device, RSS/smaps/cgroup/swap
e census comune, conservando l'esenzione W realmente residente.

[Nsight Systems](https://docs.nvidia.com/nsight-systems/UserGuide/index.html)
può tracciare allocazioni/deallocazioni CUDA e la timeline;
[CUPTI](https://docs.nvidia.com/cupti/main/main.html) associa runtime/driver
e attività GPU tramite correlation ID. La curva delle malloc esplicite
non misura automaticamente tutta la memoria del driver. Fissare versioni,
capacità dei buffer del profiler e completezza dei record; contare anche
la strumentazione nel picco, con file privati bounded e nessun valore W/A/KV.
Acquisire una baseline senza profiler per quantificarne la perturbazione.

**Discriminante.** Un incremento HBM coincidente con una nuova capacità
owner attribuita identifica memoria applicativa; un incremento con live
capacity costante e una nuova famiglia/kernel identifica una pista runtime,
stack o caricamento modulo, da isolare in un secondo componente dello stesso
kernel e shape. Se non vi è né allocazione visibile né nuovo kernel, servono
eventi driver e allocazioni interne: non chiamarlo leak o cache dimostrata.
Verificare se il livello resta dopo free/fence e se cresce al secondo gruppo
identico. Code, stack e blocking restano fissi durante questo confronto.

**Stop.** Cap originali 5.905.580.032 B payload/6.174.015.488 B fisici,
margine GPU, OOM/swap/deadline e riserva di chiusura invariati; stop anche
per record profiler persi o monitor incompleto. Conservare l'ultimo evento
e campione. Nessun nuovo tentativo di configurazione senza una domanda
discriminante; un componente positivo non ammette il picco canonico.

## 2. Il flag riusato riduce il wall del caller reale?

**Baseline/input.** Prima della modifica, confrontare il runtime di
`072de372` con il nuovo sullo stesso owner, Γ, input nonzero e shape.
Primo livello: sequenze Matrix/RNE, Affine/RNE, RMS, QK/EXP30/PV con code
ragged/tre contesti e PCS sink contemporaneamente attivo. Secondo livello:
inferenza scalare O=0 e replay A ordinato, dopo parità reale. Alternare almeno
tre ripetizioni senza profili nel confronto temporale, separando W load,
installazione, warmup, inferenza e replay. Nessun prefill batch reintrodotto.

**Misura/discriminante.** Wall del caller, tempi API malloc/free,
completamento/fence, gap CPU/GPU, kernel e copie; delte del ledger ai confini,
memoria host/device simultanea e pool di 256 B. Numero e ordine dei kernel,
byte e controlli devono coincidere; numerica, token, istogrammi, roots e
wire/FS/MAC nei consumer pertinenti devono coincidere. La riduzione del
numero di malloc senza riduzione del wall lascia l'ipotesi prestazionale
negativa. Se il costo dominante resta in mapping di grandi output o in
kernel piccoli, non estendere il pool indiscriminatamente.

**Stop.** Prima differenza numerica/ordine/causalità, errore flag/fence/free,
superamento memoria o deadline. Non allentare la sincronizzazione per
migliorare i contatori. La fixture locale prova algebra, lifecycle e conto
del pool; non dimostra né CUDA reale né accelerazione H100.

## 3. Quanto è competitivo il nostro esecutore esatto?

**Baseline/input.** I 84,382 s riguardano il nostro esecutore, non un limite
inferiore dell'inferenza di Gemma. Scegliere sulla nuova H100 un motore
ottimizzato che supporti davvero checkpoint e architettura pinned, registrando
versione/backend/precisione. Stessi prompt di 100 token, 50 generati, O=0/
150/300, singola richiesta, warmup esplicito e caricamento W separato.
Contare anche il consumo dell'ultimo token emesso in KV, senza emetterne uno
ulteriore; tokenizzazione/template e maschere devono essere gli stessi.

**Misura/discriminante.** Prefill, ciascun decode, completamento KV finale,
wall totale e memoria. Affiancare un percorso teacher-forced sui token
ammessi per confrontare identiche forme e storia, e un run di generazione
libera per osservare eventuali token diversi. Distinguere pesi originali
BF16 da W quantizzata/dequantizzata e aritmetica floating dalla relazione
intera: il motore convenzionale è un confronto prestazionale e numerico,
non un oracolo di parità del protocollo. Un risultato più veloce localizza
il margine dell'esecutore; non riduce automaticamente il costo RMS/PCS.

**Stop.** Supporto checkpoint/mask/KV insufficiente, input diverso, precisione
non dichiarata, overflow/non-finiti, budget/deadline. Non inventare un numero
per il confronto oggi assente e non trasferire la sua qualità a Γ.

## 4. Le scale candidate migliorano la prova conservando calcolo utile?

**Baseline/input.** Γ ammesso come riferimento; una candidata per trial,
stessi byte W/esponenti W/architettura/workload/ricette. Prima confrontare
su input fissati i circuiti RMS del compilatore e i loro coefficienti GKR,
separando build, replay64, core Fp3 ed endpoint byte. Solo le candidate
motivate dallo screen locale meritano un trial sui pesi reali.

**Misura/discriminante.** Larghezze/profondità, supporti, lavoro Fp3 e callback,
capacità compiler/replay/GKR, range e shift; poi errore numerico su nonzero,
quantità di output azzerati, margini, token/logits/decisioni e copertura nei
tre contesti. A live byte, D34, S1, numero di query e 512 ricostruzioni non
si considerano diminuiti senza un cambiamento reale della loro geometria.
Un costo inferiore con output banalizzati è una candidata da scartare.
Per inferenza, separare effetto delle scale da quello del flag riusato.

**Stop/obblighi.** Errore compiler/alias, overflow, degenerazione o fallimento
dei criteri numerici/qualità concordati per il workload. Nessun tempo CPU
diventa previsione H100. Nuovi token sono consentiti nello studio, ma non
ereditano ammissione: tabelle certificate, due replay interi, confronto
indipendente esatto, ledger e tutti i cinque controlli sono obbligatori
prima di sostituire Γ. Nessuna candidata viene selezionata in questa fase.
