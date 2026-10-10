# C7.1 — seguito locale: padding zero, attribuzione e RMS

Seguito autorizzato dalla conferma «ok prosegui», sul branch
`exploration/c71-local-20261010`, partendo da `8421fada` pulito. Conserva la
[chiusura locale precedente](local-exploration-close-2026-10-10.md) e la
[baseline H100](h100-campaign-close-2026-10-10.md). Nessun pod, nuova spesa,
scaricamento di packed/tracce, esecuzione completa pesante o timeout esteso.
Γ ammesso rimane byte-identico; nessuna prova o PCS per token.

Il [record](../../benchmarks/results/c71-local-followup-2026-10-10-f9a738ae5ea7.json)
conserva 84 nuovi artefatti, comandi, log, hash, esiti negativi e provenienza.
Ricontrolla tutti i 378 artefatti del record locale precedente, inclusi gli
input/metadati riusati. Le regressioni iniziali usano sorgente pulita
`e785fb1e` e il relativo digest del binario; la sola correzione successiva
della fixture Γ, `f9a738ae`, è ricompilata e ritestata su albero pulito.
Non si attribuiscono i tempi del primo binario al secondo. Gli input reali
completi restano assenti: nessun dato mancante viene ricostruito per ipotesi.
Tutto è `credit:false`, senza ammissione Γ, parità CUDA reale o tempo H100.

## Zero pubblico a Γ invariato

Il caller reale è `canonical_device::public_padding`: score raw e Z hanno
padding i64 zero; E conserva il suo padding EXP30 `2^30`. La nuova branch
pointwise `(a=0,b=0,multiply=0)` usa `cudaMemsetAsync` degli esatti `8N` byte
logici. Conserva ordine, guardie di owner/offset, input inutilizzati,
allineamento/capacità/alias e stream, reset del flag, D2H dello stato, fence,
fail-closed e pubblicazione solo dopo completamento. La validazione del
launcher è estratta senza cambiare condizioni e condivisa col nuovo fill.
Non aggiunge buffer, pooling o retention; la coda allineata non viene letta.

Il [confronto identico](../../benchmarks/results/c71-local-followup-2026-10-10-f9a738ae5ea7/zero-counter-comparison.json)
misura **7→0 lanci applicativi**, sulle lunghezze 1/3/8/255/256/257/16006.
I raw sono esattamente uguali; restano 134.288 B scritti negli output, otto
allocazioni, sette rilasci prima del close, 256 B trattenuti, owner 42.096 B,
21 fence e 134.316 B D2H inclusa l'osservazione della fixture. Il contatore
dei memset cambia 28→134.316 B perché ora include il fill dell'output:
non è riduzione del traffico di scrittura. La fixture verifica inoltre
cinque errori terminali, quattro input inutilizzati e flag sticky byte
separato. Il primo test di sviluppo aveva scelto una word valida signed32,
contrariamente alla sua aspettativa di overflow; il log fallito rimane.
La correzione riguarda solo l'input sintetico del test.

Il [census pubblico](../../benchmarks/results/c71-local-followup-2026-10-10-f9a738ae5ea7/executor-census.log)
verifica nei tre contesti **3.840 fill per scan A completa**:
60 layer ×32 teste ×2 sorgenti. Nei 512 replay iniziali sono **1.966.080**
lanci pointwise applicativi evitati. Non riguarda inferenza, scan parziali
o run interrotti. Il lavoro interno CUDA del memset può includere kernel
e allocazioni: nessun credito al numero totale di kernel GPU o al wall.
Il batching ritirato non è reintrodotto. Il ledger di default resta
5.878.735.106 B, `joint_admitted:false`; questa modifica non risolve lo spike.

## Traccia bounded dell'owner e clock comune

La build esplicita `-DC71_OWNER_TRACE` aggiunge solo 32 B all'owner,
**42.128 B** contro 42.096 B di default, addebitati dal callback esistente.
Traccia before/after delle due sedi `cudaMalloc`, delle free effettive e
della fence comune; slot pubblico, kind, byte logici/capacità, ledger,
funzione/linea, esito e timestamp `CLOCK_MONOTONIC`. Non registra handle
opachi, puntatori, capacità crittografiche, monete o valori W/A/KV. Non è
una timeline kernel/copie e non contiene correlation ID CUDA.

`C71_OWNER_TRACE_PATH` deve essere assoluto e nuovo, con file privato 0600,
creazione esclusiva/no-follow e durabilità iniziale/finale. Nessun heap o
buffer stdio del logger: record su stack da 512 B; massimo **131.072 record
o 16 MiB**, senza estensione automatica. Un errore di logging ferma
l'owner, mantenendo cleanup e debito nativo. Post-event dopo bookkeeping;
una free già fallita non è ritentata né rappresentata come nuova API.
Passano 26 casi dell'header e 12 processi/scenari di integrazione con fault
prima/dopo alloc/free/fence, ritiri e snapshot. Nessun CUDA reale.

Il selettore facoltativo `C71_OWNER_TRACE_A_FIRST=0..511`, in decimale
canonico, arma la traccia al corrispondente `source_begin` validato e salta
gli eventi precedenti di inferenza/setup. All'arming registra W e ogni
buffer vivo come **retained snapshot**, non come malloc avvenuta allora.
Un gruppo richiesto ma mai raggiunto rende il cleanup diagnostico fallito.
`a_group` significa **ultimo begin validato**: Rust alloca low/high e
values/histogram del gruppo successivo prima di quel begin, quindi questi
eventi possono avere ancora il gruppo precedente. Funzione/linea e lifecycle
degli slot restano necessari per l'attribuzione. La copertura sul workload
reale e il tasso di eventi non sono verificati: il file bounded può terminare
prima della finestra desiderata. Una traccia immediata non coprirebbe tutta
l'inferenza, già oltre il suo cap contando le sole fence numeriche.

Il monitor CSV conserva le vecchie colonne e aggiunge in coda gli estremi
monotonic dell'intera raccolta. Il journal Rust emette un'ancora iniziale
con gli estremi monotonic intorno a `Instant::now`: gli `elapsed_ns`
esterni si allineano sommando quell'intervallo, non sommando i `wall_ns`
delle fasi. Il bracket include chiamate nvidia-smi/proc/cgroup/disco:
non rende simultanee le letture, non misura picchi istantanei né sincronizza
gli eventi GPU. Passano il test durevole, il bound dello schema e 36 test
del monitor; restano necessarie timeline CUDA e calibrazione del clock del
profiler. L'ancora resta fuori dal wire/FS e non abilita resume.

La build host dell'header, `g++ -O2 -fstack-usage`, misura frame statici di
4.288 B per open e 656 B per emit. Si riservano conservativamente 8 KiB
all'apertura e 1 KiB in emit, oltre allo stato e alla cache del contenuto
del file fino a 16 MiB, che può sopravvivere al close. Frame del caller,
libc/CUDA, metadata/cache filesystem, profiler e compilatore H100 restano
da contabilizzare: il conto diagnostico non eredita un'ammissione fisica.
La build default non contiene il logger. Non è disponibile nvcc locale;
questa sessione non compila CUDA.

## Screening Γ: predicato originale, supporti e memoria packed

Le due fixture usano ricette trattenute reali, rispettivamente
`(256,-5,-18,-13,weighted)` e `(512,-5,0,-9,unweighted)`, con i bucket pari
coarser/finer e W sintetica fissata. Gli input dyadici mantengono la stessa
grandezza fisica senza arrotondamento fra scale; P/S/Y provengono da
`Integer::row`. Ogni fixture verifica **75 casi da righe e 60 casi delle
sole soglie del predicato**, con nonzero, entrambi i segni, zero, Y±1/sign
alterati e marker vietato, quattro pareggi signed esatti e vicini alla
soglia. I casi delle sole soglie non pretendono di essere witness P/S
coupled di una riga reale o calibrazione della qualità.

Confronta replay Boolean completo, layer e packed su depth 0/32/finale,
ordine esatto dei getter, celle `None` e lane di padding; confronta
coefficienti Fp3 del supporto/primo round con il calcolo letterale a depth
1/32 e prefissi 0/1, selettori extension e programmi non supportati.
Contatori e capacità packed trattenute sono registrati, incluse capacità
inattive e old/new durante crescita. Il primo controllo unweighted fallisce
per indici tutti negativi salvo zero: 256 e 511 sono entrambi 1 modulo17.
Sostituire l'indice intermedio con 16 garantisce il positivo, senza cambiare
X/W, ricette, numero di casi o assert. Il failure pulito e i due retest
corretti restano nel record; nessun controllo è allentato.

Lo [screen analitico](../../benchmarks/results/c71-local-followup-2026-10-10-f9a738ae5ea7/packed-analytic-upper-output.json)
riusa 398 metadati già compilati, verificando manifest, tutti i batch,
candidate e oracle. Segue l'ordine del caller tramite S/ordinal, controllando
che qui coincida con quello causale; pinna liste/digest delle chiavi.
Per ogni depth 0..98 conta soltanto And/Xor per nodi/hash, output selezionati
e larghezza effettiva. Somma piani precedenti col builder corrente;
scratch usa le capacità massime dei load, non l'ultimo bisogno. Il packed
muore prima di indexedges/byteLUT e non si accumula fra depth.

| Screening O=0 | Packed più fixed storico, upper B | Circuit più PYS più packed, subtotal upper B |
|---|---:|---:|
| Γ ammesso |325.906.729|2.807.071.599|
| RMS pari coarser |191.732.984|2.475.849.726|
| RMS pari finer |193.965.966|2.481.204.756|

I massimi sono al depth selezionato 98; le capacità scratch massime al
depth74 sono 346.112/345.472/345.704 B. Si confrontano **limiti superiori**,
non risparmi di memoria misurati. Sono basati sui layout64 e sulle regole
Vec/hash pinned già usate dal runtime, senza ottenere il DAG esatto.
Il ledger conserva il suo upper generico packed 387.537.052 B. Il nuovo
subtotal include PYS invariato **2.023.511.878 B** e la capacità dei circuiti
simultanei, ma esclude profiles, statistiche/proof/pending/triples/products,
round GKR, PCG/correlazioni/sessione/FS/serializzazione, allocator, Builder
del compiler originale, stack macchina e W/setup/A dei due ruoli.
Non è un nuovo bound completo né una spiegazione dello spike iniziale A.

L'ordine delle candidate resta quello della
[chiusura precedente](local-exploration-close-2026-10-10.md#candidate-γ-ordinate-e-obblighi):
prima coarser (core Fp3 −13,9216%), poi finer condizionata (−14,4015%, rischi
i16 baseline in 16/5/2 fonti); variazioni dei soli output scartate come
ottimizzazioni. Profondità, celle vive/callback, A/D34/512 ricostruzioni,
PYS e PCS restano invariati. Nessuna fixture scarica qualità, rischi sui
nuovi valori upstream, ricalibrazione, replay completi indipendenti,
ledger completo, controlli d'ammissione o premesse Lean aperte.

## Verifiche e prossime domande

Passano **nove test Rust distinti e 40 test Python**: i due RMS nuovi,
progress/schema, due pointwise, replay A, catena PCS A con wire/FS/MAC
originali e closure lineare; due owner default, due trace e 36 monitor.
Test seriali entro 60 s/AS2 GiB, massimo test 53,248 s; due build mirate
56,770/56,018 s entro 120 s, picco RSS aggregato campionato massimo
2.595.688.448 B, sotto stop3 GiB. Le compilazioni C++/census restano
componenti ridotti. CPU time e driver simulato non predicono H100.

Confermati: eliminazione dei lanci applicativi zero, contabilità dei
lifetime/failure del logger, parità del predicato/replay/supporto ridotto.
Scartata la lettura «meno kernel significa meno scritture/memoria»;
pooling generale, batching, qualità Γ e causa dello spike restano senza
nuova selezione o prova. NoPeek, MAC originali, AES-PCG, correlazioni
monouso e fail-closed rimangono invariati.

## Verifiche hardware prioritarie dopo il seguito locale

Questo è un piano, senza esecuzioni hardware. La prossima campagna richiede
autorizzazione distinta per hardware e durata; nessun pod, spesa, trial pesante
o prolungamento dei timeout è autorizzato dal lavoro locale. Restano Γ ammesso,
NoPeek, MAC originali, correlazioni monouso, PCG AES e fail-closed.

1. **Lo spike A è capacità applicativa o memoria interna CUDA?** Baseline:
   A06 canonico, con W/setup trattenuti; A04 resta componente differente.
   Input: Γ ammesso, W verificata, shape reali, stack/code invariati, monete
   nuove. Partire dal gruppo precedente quello sospetto. Build diagnostica
   `C71_OWNER_TRACE`: owner 42.128 B, incremento 32 B; scegliere
   `C71_OWNER_TRACE_A_FIRST` per saltare l’inferenza. All’arming, snapshot di W
   e di tutti gli slot vivi: sono capacità trattenute, non eventi malloc.
   `a_group` indica l’ultimo `source_begin` validato: allocazioni preparatorie
   successive possono portare ancora il gruppo precedente. Sequenza,
   funzione/linea, slot, kind, capacità ed esiti ricostruiscono i lifecycle.
   Trace massimo 16 MiB/131.072 record; il censimento del tasso di eventi e
   la copertura della finestra richiesta sono prerequisiti, senza estendere
   automaticamente il cap. Contare anche 8 KiB stack d’apertura, stack emit,
   fino a 16 MiB di cache del contenuto, filesystem e profiler; la cache può
   sopravvivere a close.
   Collegare CLOCK_MONOTONIC owner all’ancora Rust e agli intervalli CSV;
   Nsight Systems/CUPTI esterni, con allineamento clock verificato, devono
   fornire eventi CUDA e correlation ID, assenti dal trace owner. Misurare
   live capacity, API/kernel/fence, HBM intero device, RSS/smaps/cgroup e
   residuo HBM meno capacità device. Aumento owner attribuito oppure owner
   costante con attività CUDA diversa distingue le piste; nessuno dei due
   prova automaticamente leak o cache. Confrontare anche senza profiler.
   Stop: perdita di record, finestra incompleta, cap trace/arena, payload
   5.905.580.032 B o fisico 6.174.015.488 B, margine GPU, swap/OOM/deadline e
   riserva di chiusura; conservare il prefisso fallito.

2. **Pooling e padding zero riducono il costo dei caller reali?** Confronti
   separati: `072de372` contro `8421fada` per il pool; `8421fada` contro
   `871295e2` per il padding zero. Stessi Γ/W/input nonzero e ordine; parità
   CUDA prima delle misure. Padding: solo replay A con padding pubblico,
   nessun credito d’inferenza. Pool: producer reali e replay ordinato.
   Alternare ripetizioni senza profiler; separare installazione, warmup,
   kernel, copie/fence e malloc/free. Misurare wall, contatori e memoria
   simultanea, verificando risultati numerici, consumer/MAC e sincronizzazioni
   richieste. Meno chiamate senza meno wall lascia negativa l’ipotesi
   prestazionale. Stop al primo mismatch, errore CUDA o superamento budget.

3. **Quanto margine lascia un motore d’inferenza ottimizzato?** Baseline:
   84,382 s del nostro esecutore intero esatto. Stesso checkpoint/architettura,
   prompt 100 token, 50 generati, O=0/150/300, maschere e consumo KV finale;
   motore/versione/backend/precisione dichiarati. Separare W load, prefill,
   decode e memoria. Teacher forcing sui token ammessi distingue costo a
   storia identica; generazione libera misura divergenze. BF16 originale e W
   quantizzata/dequantizzata restano confronti distinti, senza parità di
   protocollo. Stop per supporto workload insufficiente, non-finiti o budget.

4. **La candidata RMS coarser conserva qualità e riduce quale costo?**
   Riferimento Γ ammesso, stessi W/esponenti W/architettura/workload/ricette.
   Prima fissare criteri di errore, output nonzero e decisioni sui pesi reali;
   poi separare compiler, plan build/replay64, core GKR ed endpoint byte/PCS,
   con capacità simultanee e lavoro aritmetico. A/geometria e 512 ricostruzioni
   restano invariati. Stop per overflow, alias, degenerazione o criteri
   falliti; screening senza ammissione. Sostituzione solo dopo calibrazione,
   controlli completi e ledger nuovo, senza prove o PCS per token.
