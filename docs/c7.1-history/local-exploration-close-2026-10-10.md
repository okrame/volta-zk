# C7.1 — chiusura delle esplorazioni locali, 10 ottobre 2026

Lavoro autorizzato dopo la [chiusura H100](h100-campaign-close-2026-10-10.md),
partendo da `072de372a3d1038b037856950bfffb84657920af`, albero pulito.
Branch dedicato `exploration/c71-local-20261010`. Nessun pod, spesa,
scaricamento di pesi/tracce o esecuzione completa pesante; nessun timeout
esteso. Le cinque istruzioni correnti sono in [design](../c7.1/design.md).

Il [record nuovo](../../benchmarks/results/c71-local-exploration-2026-10-10-f71a12519ad9.json)
conserva 378 artefatti, input, output, log, comandi, hash e ricevute, senza
sovrascrivere record precedenti. Le misure principali usano sorgente pulita
`102ecf02ab98`; il solo aggiornamento successivo della fixture di replay,
`f71a12519ad9`, è ricompilato e ritestato su albero pulito. Il record
esplicita entrambe le provenienze: non attribuisce i vecchi tempi a un
nuovo binario. Tutto è `credit:false`; non è una nuova ammissione fisica,
una prestazione completa o una sostituzione di Γ.

## Baseline e lacune

L'[inventario iniziale](local-baseline-exploration-2026-10-10.md) verifica
54 manifest, 3.134 file manifestati presenti e quattro ritiri con receipt;
31 record pubblici e 932 artefatti collegati. Il deposito effettivo ha
3.242 file / 234.830.264 B. La nuova verifica su sorgente pulita, nel
[record](../../benchmarks/results/c71-local-exploration-2026-10-10-f71a12519ad9/inventory-rechecked.json),
riconferma tutti i byte/hash. La receipt Γ ricalcolata dai report trattenuti
è identica all'originale; non ripete i replay completi. Packed W, shard e
tracce numeriche complete sono assenti; non sono stati scaricati.

**84,381738 s** è il tempo del nostro esecutore intero esatto, O=0,
150 token. Manca il confronto con un motore di inferenza ottimizzato sullo
stesso workload. Caricamento W, residenza, installazione, setup dei due
ruoli simultanei e preparazione sono intervalli distinti, alcuni inclusi
in altri: non si sommano indiscriminatamente. Contatori owner cumulativi,
upper tipati e campioni RSS/HBM hanno ambiti distinti.

La campagna conserva zero certificati accettati, A06 fermo a 35/512 gruppi,
A04 a 86/512, con spike HBM di 504/509 MiB. Le capacità owner non sono
sincronizzate con il campione terminale: manca l'attribuzione delle
allocazioni e degli eventi CUDA. A04 omette W commitment/setup e non
fornisce credito al picco canonico. Blocking e code ridotte non risolvono
lo stop. L'inferenza in batch resta ritirata: +45,71% wall nonostante
−65,98% circa di allocazioni, kernel e fence. Gli observer mostrano
mmap/munmap durante molti campioni batch con GPU inattiva; è una pista,
non una causa misurata per sito. Nessun batching viene reintrodotto.

## Modifica dell'esecutore a Γ invariato

Il [flag numerico riusato](local-executor-2026-10-10.md) riguarda gli undici
caller sincroni reali. Un solo flag privato da 4 B, capacità **256 B**,
viene azzerato sullo stream prima di ogni operazione. Letture di errore,
fence, kernel, ordine, output e guardie restano invariati; i flag sticky
PCS/byte sono separati. Il pool occupa una entry su 512 e il campo owner
aggiunge **8 B host**, `sizeof` **42.096 B**. Tutta la capacità trattenuta
resta nel conto fino a cleanup; una free fallita conserva il debito.
Il contatore `releases` include ora le free di buffer riuscite nel close.

Il [confronto identico prima/dopo](../../benchmarks/results/c71-local-exploration-2026-10-10-f71a12519ad9/flag-counter-comparison.json)
misura **32→1 allocazioni** del flag su 32 pointwise nonzero, con stessi
32 kernel, 96 fence e 2.176 B D2H inclusa l'osservazione dei raw.
Nessun tempo CPU della fixture è un guadagno H100. Il census del piano
pubblico coincide con launch/D2H della baseline H100 e predice
**1.185.769** coppie alloc/free in meno per inferenza, −32,5652% delle
allocazioni native se il resto resta uguale; nei 512 replay completi A
sono **6.997.504**. Non sono tempi o numeri di tutti i consumer parziali.

Il ledger nominato conserva 653 fasi e undici classi: nuovo massimo
**5.878.735.106 B**, headroom **26.844.926 B**. Conta il pool anche inattivo
e corregge il lifetime del setup AES, che avviene con W/cache/owner già
installati. Non sottrae implicitamente flag negli upper storici e non
trasforma il subtotal in allowance verificata: `joint_admitted:false`.
Raw+RNE, output, KV, staging, cache e workspace simultanei restano contati.
Pooling generale, fusioni o nuove code restano ipotesi senza selezione;
trattenere grandi buffer può peggiorare proprio la fase PCS A.

## Candidate Γ ordinate e obblighi

Lo [screening Γ/RMS](gamma-screen-2026-10-10.md) conserva W/esponenti W,
architettura, workload, ricette numeriche, embedding e Pi; varia al massimo
un bit delle scale RMS compatibili con gli alias. Γ ammesso resta
byte-identico. I costi seguenti riguardano **solo il core RMS/GKR CPU di
una risposta O=0**, dopo pruning e primo round esatto; non tutta la prova.

| Priorità | Candidata | Programmi | Prodotti Fp3 core | Byte posseduti dai programmi | Compatibilità e limite |
|---|---|---:|---:|---:|---|
| Riferimento | Γ ammesso |159|844.006.203.160.300|457.634.736|Ammissione precedente invariata |
| 1 | Esponenti RMS al pari più grossolano |91|726.506.808.569.837 (−13,9216%)|260.594.224 (−43,0563%)|Compiler tre contesti PASS; qualità ignota |
| 2, condizionata | Esponenti RMS al pari più fine |92|722.456.626.804.641 (−14,4015%)|263.716.160 (−42,3741%)|Compiler PASS; rischio requantizzazione baseline in 16/5/2 fonti |
| Scartata come ottimizzazione | Solo output +1 |159|843.748.781.625.796 (−0,0305%)|457.331.376|Beneficio trascurabile; compiler completo in timeout |
| Scartata come ottimizzazione | Solo output −1 |159|844.491.117.794.189 (+0,05745%)|458.192.112|Costo maggiore e rischio in 8/4/2 output; timeout |

Tutte mantengono **profondità 99, 347.937.024 celle vive, 998.927.195.904
callback**. Le larghezze aritmetiche massime possono aumentare 101→103
anche coarsening. Le righe del solo GKR core sono 17.254 riferimento,
17.248 coarser, 17.254 finer: non è la prenotazione RMS/PCG completa.
A mantiene le tre lunghezze byte, D34, **512 ricostruzioni**, checkpoint
PYS **2.023.511.878 B**, piano PCS e nessuna prova/PCS per token.
La riduzione dei programmi non interviene nello spike iniziale A.
Il possesso dei Circuit/Vec misurato dal compilatore esclude Builder,
allocator, packed replay, workspace e simultaneità dei due ruoli: nuovi
upper completi sono obbligatori, non si ereditano quelli del Γ ammesso.

La fixture RMS sintetica verifica 1.263 output nonzero per candidata,
zero overflow e bound RNE sulla stessa grandezza fisica con W fissata
sintetica. La baseline reale conservata segnala i rischi delle varianti
finer, senza eseguire nuovi valori upstream. Nessuno dei due controlli
prova qualità. Servono pesi reali, teacher forcing nei tre contesti,
errori RMS/max dequantizzati per layer, frazioni zero/saturazione, drift
attenzione/logit, margini argmax e qualità di generazione con soglie
predefinite; poi due replay interi, confronto indipendente esatto, KV
finale e tutti i cinque controlli d'ammissione. Token diversi non ereditano
Γ. Ricalcolare riserva di correlazioni e bound pubblici di sicurezza e
risorse applicabili; nessun risultato locale scarica le premesse Lean.

## Verifiche, fallimenti e passo successivo

Passano **17 test Rust distinti e 11 test Python**: Matrix/RNE, RMS,
pointwise, embedding, attention O=0/150/300, copertura/replay A, root e
catena PCS con wire/FS/RNG/MAC originali, closure lineare e range denso;
inoltre driver differito con UBSan, identità Γ e conto del pool/setup.
I 50 batch delle 398 ricette RMS passano; i due profili pari completano
il compiler nei tre contesti. Tutti i test sono seriali, ≤60 s / AS 2 GiB;
build mirate ≤120 s con stop RSS aggregato 3 GiB, massimo osservato
2.599.170.048 B. Driver simulato non è parità CUDA reale.

Si conservano separatamente i fallimenti di sviluppo (residuo embedding,
Pi scelto come istogramma, aspettativa del ledger), il failure pulito della
fixture fredda di replay e il retest corretto a **12,502 s**. Non si concede
una tolleranza per ogni scan: quello caldo deve mantenere il totale vivo.
Le ricompilazioni complete del riferimento e delle due candidate output
si fermano a **60 s / exit 124**, stdout vuoto conservato, senza retry.
Il primo driver senza `/usr/bin/time` fallisce prima del compiler; il
successivo usa `os.wait4` e un'altra directory. Il build example in profilo
test produceva un harness, non la CLI: entrambi i log e il successivo
build dev corretto sono conservati. Nessun esito negativo è riscritto.

Sono correggibili i documenti attivi, non i record congelati: Tensor W è
selezionato dopo le parità H100, attention MMA resta non selezionata; gli
ingressi hardware lineari esistono e hanno già passato la campagna.
Il nuovo conto distingue setup dopo W e retention del flag. NoPeek,
MAC originali, correlazioni monouso, AES-PCG e fail-closed restano invariati.

Il [piano hardware](local-hardware-plan-2026-10-10.md) prepara quattro domande:
(1) quale allocazione/evento provoca lo spike A? (2) il pool riduce wall
nei caller reali a lavoro identico? (3) quanto dista l'esecutore esatto da
un motore ottimizzato sullo stesso workload? (4) il bucket coarser conserva
qualità e realizza il minor costo del core senza spostarlo altrove?
Ogni esperimento ha baseline, input, strumenti, discriminante e stop.
Nessuno è eseguito: una nuova campagna richiede nuova autorizzazione.
