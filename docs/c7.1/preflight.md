# C7.1 — preflight locale, 2026-09-13

**Esito: NO-GO per una spesa H100.** La schedule range migliora; il
preflight completo di ammissione non è ancora soddisfatto. Il rapporto
riproducibile è `scripts/c71_streaming_screen.py`, campi `local_preflight`
e `coset_Merkle_frontier`, entrambi `credit:false`. `null` significa
costo ignoto, con upper di ammissione infinito. Nessun pod è stato creato.
Questo documento prepara controlli e comandi; non chiede né concede spesa.

## Banda e calcolo: due lower distinti

Per un kernel/stadio k, i lower necessari sono `B_k/BW_max` e
`I_k/R_max`. Lo stesso kernel può eseguire IO e calcolo insieme:
`max(B_k/BW_max,I_k/R_max)` è un lower, non la loro somma e non un upper.
Tra stadi dipendenti sommare i tempi completi; non presumere overlap
fra inferenza, witness/range, PCS, PCG e serializzazione. Non aggiungere
una seconda volta l'IO già incluso nel tempo del kernel.

Il riferimento [NVIDIA H100 SXM](https://www.nvidia.com/en-us/data-center/h100/)
riporta 80 GB e 3,35 TB/s. È un picco, non banda effettiva del gather.
Per la schedule range da 26 visite, il payload W è 1.596.261.954.560 B.
Con allocazioni non compresse e al più 256 MiB di riuso on-chip per visita,
la sola lettura W impone **>=0,474413 s** a quel picco. Il margine cache
è volutamente maggiore di L2, registri e memoria locale condivisa del
riferimento; le [specifiche Hopper](https://docs.nvidia.com/cuda/hopper-tuning-guide/index.html)
distinguono questi spazi e l'attivazione esplicita della compressione.
Accessi non coalescenti e temporanei aumentano il traffico: non trasformare
0,474413 s in una previsione o in un upper.

Per il calcolo intero, usare un census delle istruzioni native compilate,
separando mul/MAD, add, shift e altre classi. Il bound per la pipeline
mul/MAD INT32 del riferimento è `I_mul_min/(132*64*f_max)`; frequenza
massima e SKU vanno fissati, le latenze non sono throughput. La
[tabella CUDA](https://docs.nvidia.com/cuda/archive/12.9.1/cuda-c-programming-guide/index.html#arithmetic-instructions)
conta risultati per ciclo/SM e avverte che le operazioni composte
cambiano con il compilatore. **Non esiste ancora un lower numerico di
calcolo nativo verificato**: manca SASS, poiché nvcc non è installato
localmente. Come sola sensibilità, ipotizzare 9 istruzioni mul per ogni
mul Fp3 del nucleo e un ceiling di 2 GHz dà 1,676 s; nessuna delle due
ipotesi sostituisce il census del binario. Non usare TFLOPS FP8/FP16
Tensor Core come throughput Fp/Fp3.

C'è invece già un **NO-GO dimostrato per il port FFT letterale** del primo
oracolo PCS W: 22 kernel globali radix-2, senza fusione, su ogni coset da
4 GiB richiedono almeno
`1024*22*2*(4 GiB-256 MiB) = 181.419.418.583.040 B`, con le stesse
condizioni di cache/compressione. Sono **54,155050 s per un solo passaggio
PCS**, senza leggere W o fare hash. Questa implementazione è scartata.
Il bound non esclude FFT a blocchi/fuse, descritte sotto.

## Throughput necessario, non sufficiente

La colonna /50 concede ottimisticamente tutti i 50 s alla singola voce.
Con un budget assegnato t_k, il requisito diventa `work_k/t_k` e la somma
dei budget dei componenti deve essere <=50 s. Passare tutte le soglie /50
non basta; mancano lavoro escluso e rallentamenti del reader integrato.

| Voce | Lavoro noto | Soglia /50 s |
|---|---:|---:|
| Merge range W | 640.151.453.695 merge | 12,803 Gmerge/s |
| Accumuli child range | 506.403.487.744 | 10,128 Gaccumuli/s |
| Costruzione H, mul Fp3 | 709.743.345.664 | 14,195 Gmul/s |
| Coefficienti cubici residenti, kernel 18-mul | 369.098.716 bucket | 7,382 Mbucket/s |
| Fold scalari range, H incluso | 1.845.496.145 | 36,910 Mfold/s |
| Nucleo range confrontabile a 27-mul/bucket | 3.146.566.859.825 mul Fp3 | 62,931 Gmul/s |
| Riduttore W suffix-first | 314.498.580.480 aggiornamenti | 6,290 Gaggiornamenti/s |
| PCS primo oracolo W, scaling generico per replay | 35.184.573.415.424 mul Fp | 703,691 Gmul/s |
| PCS FFT, per replay | 6.047.313.952.768 butterfly Fp | 120,946 Gbutterfly/s |
| PCS twiddle fra le due FFT locali, per replay | 549.755.813.888 mul Fp | 10,995 Gmul/s |
| PCS leaf hash, per replay | 4.294.967.296 righe da 128 Fp + 4 sali | 85,899 Mleaf/s |
| PCS internal hash, per replay | 4.294.967.295 compressioni | 85,899 Mnode/s |
| PCS completa W/A/vecchie A, PCG, range A, inferenza, serializzazione | Non censiti completamente | Non determinabile; gate fallito |

Il nucleo range comprende già merge/accumuli/H/coefficienti: non sommare
quelle righe al nucleo. Il kernel fattorizzato abbassa il nucleo a
3.143.244.971.381 mul Fp3. Le righe PCS scaling contano il riferimento
generico, pad compresi; il padding W pubblico può essere specializzato,
ma la specializzazione deve aggiornare anche kernel e conteggio.

## Liveness integrata e picco

Ordine imposto dal transcript: output e challenge dei producer; istogrammi
corretti prima di alpha/rho; range W con canopy e livelli inferiori;
range A e target richiesti; lambda del batch W; 15 round suffix-first;
seconda visita e ultimi 20 round; PCS al punto riportato nell'ordine
originale. Non anticipare C del range o query PCS ancora ignote.

Piano: un'arena preallocata da **6.442.450.944 B**, con viste riusate solo
dopo ultimo consumer e completamento GPU. Le cifre seguenti sono
prenotazioni di progetto, non tracce di un allocatore già integrato.

| Fase | Array/workspace pianificati, B | Rilascio / condizione |
|---|---:|---|
| Canopy range | 6.308.757.448 | 5.234.491.344 nominati + 1.006.632.960 destinazione fold + 64 MiB scratch + istogramma; rilasciare dopo terminale top |
| Finestre H | <=256 MiB di slot + istogramma | Worker in numero fisso; H massima 24.576 B, child 3.072 B, stack; nessuna H per tutti i bucket |
| Range residente 25 bit | 6.315.073.528 | 6.046.113.792 sorgenti/destinazione fold/riduzione + 256 MiB scratch + istogramma |
| Linear primi 15 round | C=2.848.456.704, più scratch da censire | Rilasciare C dopo target autenticato del round 15 |
| Linear secondo passaggio | B/L=50.331.648, più scratch da censire | Rilasciare dopo terminale originale prima di PCS |
| PCS primo oracolo W | 5.739.381.472 nominati | Coset, frontier, twiddle, pad, offset sali; restano 703.069.472 per reader/hash/allocator e stato vivo |
| Range A, producer A/KV, PCG, PCS successive | Non chiusi | Non assegnare il residuo a zero costi |

L'out-of-place fold serve a non assumere sicuro un fold CUDA in-place
con letture/scritture concorrenti. Il microbench usa coppie contigue:
il reader canonico deve realizzare il medesimo ordine di coordinate,
non cambiare il punto MAC. Gli slot scratch indicati sono cap da rispettare
nel port, non upper misurati del codice mancante. La H parziale può essere
ridotta con un numero fisso di worker; il microbench materializza invece
H per bucket **soltanto sul suo piccolo input componente**.

Con W residente più tutta l'arena restano **12.162.858.496 B** sotto gli
80 GB per gli altri residenti. Il picco deve includere KV, stato ancora
accettato, runtime/context, workspace esterni all'arena, cache degli
allocator e materiale privato PCG trattenuto. Il picco globale **allocato
e riservato è ignoto**: `cudaMemGetInfo` da solo non certifica il massimo
né l'assenza di spill. Non accreditare l'intera tabella come schedule
fisica completa. La materializzazione densa A/D34 in elementi base richiede da sola
137.438.953.472 B: quel layout è escluso. Il numero di celle dei lookup
RNE include ripetizioni e non misura il payload A packed residente.

## Visite, traffico e PCS senza spill

| Fase | Visite W note | HBM / esterno | A/KV |
|---|---:|---|---|
| Caricamento globale W | 1 trasferimento, distinto dalle visite prover | 61.394.690.560 B esterni + destinazione HBM; tempo non sottratto dal lavoro totale | Separati |
| Commitment iniziale W, variante coset | 1.024 | 62.868.163.133.440 B payload W residente | Non incluso |
| Range W + linear per risposta nella schedule invariata | 28 | 1.719.051.335.680 B payload W residente | Range A escluso |
| Replay apertura primo oracolo W dopo query | 1.024 | 62.868.163.133.440 B payload W residente | Non incluso |
| Altri oracoli PCS, inferenza, producer/range A, KV | Ignoti | Transazioni, temporanei e copie ignoti | Visite totali ignote |

Quindi **1.052 visite W note per risposta**, più 1.024 per il commitment
iniziale, in questa candidata PCS; **2.076 nel primo prefisso**, prima
degli altri oracoli/inferenza. Il commitment installato si riusa, il suo
lavoro iniziale resta separatamente nel confronto dei prefissi 1/2/3.
Non è un totale completo né un lower universale sulle PCS. Esterno per
le sole visite a W residente: zero; serializzazione/protocollo e copie
A/KV hanno un ledger distinto ancora incompleto. Il range W una tantum
è un'ulteriore modifica formale di stato, non assunta in questi conti.

La [costruzione per coset](construction-screen.md#pcs-coset-frontiere-e-sali-riproducibili)
usa L=2^22 righe, Q=1.024 coset e indice naturale `Q*j+c`. Per ogni j si
mantiene una frontier Q-leaf; le radici arrivano nell'ordine j e sono
unite dallo stack superiore. Si conservano i pad originali e due vettori
di offset XOF per riprodurre esattamente i sali canonici, anche con
rejection sampling. Il prescan sali legge almeno 137.438.953.472 byte XOF,
nessun W; conserva il cap nativo di 2^40 con abort. L'apertura richiede
un nuovo replay dopo le query, raccogliendo i fratelli necessari; non
anticipa query, non riversa codeword o sali su disco.

La candidata FFT a blocchi fattorizza L=2048²: tre trasposizioni quadrate
in-place a tile e due FFT di riga in shared memory da 16 KiB, con twiddle
fuso nella seconda trasposizione. Sono cinque letture/scritture dell'array
per coset, **43.980.465.111.040 B logici per encoding**, oltre a W,
frontiere, sali e hash. Il rapporto `(payload W + questi byte)/3,35 TB/s`
è **31,895113 s**, solo una scala di traffico nel layout ideale; cache,
coalescing e overhead non sono misurati. Non è un upper. Il test finito
verifica l'identità della FFT nell'ordine naturale; manca il kernel
CUDA di questa FFT/reader/hash integrati. Il percorso non è respinto
per le 1.024 visite, ma non è ancora ammesso.

## Harness e input pronti

[CUDA](../../cuda/c71_range_microbench.cu) e
[harness](../../scripts/run_c71_range_microbench.py) coprono Fp3
Goldilocks `u^3=2`, merge, coefficiente cubico 18-mul contro oracle
27-mul, fold e Gram L=8/16/32. Input SplitMix64 deterministico, seed
`0xc701351125020001`, tutte e tre le limb; SHA-256 sorgente e SHA Git
completo nel record. I dati non sono pesi Gemma o un transcript valido.
Il controllo host usa anche casi limite di campo e confronti algebrici;
quello GPU confronta con CPU e fallisce prima delle allocazioni grandi.

```sh
ulimit -v 2097152
PYTHONDONTWRITEBYTECODE=1 timeout 60s python3 scripts/run_c71_range_microbench.py \
  --host-only --host-log2 8 --gram-width 32 --timeout-seconds 30
```

La prova locale non compila i rami CUDA: nvcc e GPU non sono disponibili.
Il run GPU quick usa m=18/3 ripetizioni; quello componente grande m=25/7,
con allocazione range richiesta di 6.046.113.792 B. Gram L32 usa un input
separato m=20 e 909.901.824 B, dopo il rilascio degli array range. Gli
output registrano separatamente allocazione, inizializzazione, kernel,
riduzione, delta memoria e limiti di scope. Nessun loro tempo certifica
il gather, una PCS, PCG, inferenza o prover completo.

## Comando futuro, durata e costo

SHA eseguibile verificata con tree pulito:
`05eb3583f438f044671adfd0d3ac488c7229b1c4`. Deve essere anche
**pubblicata tramite Git HTTPS** prima di una riproduzione sul pod.
Al momento il lavoro è solo locale. Il
[runbook](../procedures/runpod.md) richiede Secret repository-scoped,
`git-preflight` prima di compilare e deadline lato provider.

Solo dopo il successivo GO esplicito e i controlli sotto, la forma di
creazione prevista dalla [CLI RunPod](https://docs.runpod.io/runpodctl/reference/runpodctl-pod)
è `runpodctl pod create --image IMAGE_PINNED --gpu-id "NVIDIA H100 80GB HBM3"`
con `--gpu-count 1 --container-disk-in-gb 50 --volume-in-gb 0
--terminate-after 20m`. Prima della spesa verificare flag, GPU ID,
immagine CUDA devel fissata per digest, Secret e prezzo effettivi.
Questi valori non sono stati inventati o risolti tramite un pod pagante:
immagine/digest e provisioning restano gate aperti; la forma non è ancora
un comando di creazione completamente istanziato.

Il comando di workload sul futuro checkout della SHA fissata è:

```sh
test "$(git rev-parse HEAD)" = 05eb3583f438f044671adfd0d3ac488c7229b1c4
scripts/runpod_harness.sh git-preflight
# VOLTA_CLOUD_*: metadati reali richiesti dall'harness, non valori sintetici.
timeout --signal=TERM --kill-after=30s 600s \
  python3 scripts/run_c71_range_microbench.py \
  --quick --gram-width 32 --arch sm_90 --timeout-seconds 240
```

È **solo** il microbench quick; il run m25 richiede una sua autorizzazione.
Durata workload massima 630 s con kill, pod massimo 20 minuti; timeout
locale non sostituisce la terminazione provider. Le
[tariffe pubbliche](https://www.runpod.io/pricing) lette il 2026-09-13
indicano H100 SXM a $3,49/h: 20 minuti costano $1,1634 GPU. Aggiungendo
50 GB di container per 20 minuti a
[$0,10/GB/mese](https://docs.runpod.io/pods/pricing), circa $0,0024,
il costo atteso è **circa $1,17**, senza volume persistente. $1,25 è una
soglia di proposta, non un budget autorizzato né un cap contrattuale:
prezzo, storage e deadline vanno riconfermati prima della spesa.

## GO/NO-GO verificabile prima della spesa

| Gate | Evidenza richiesta | Stato locale |
|---|---|---|
| Algebra/endpoint | Coefficienti adattivi, terminali, root e path contro riferimento; niente nuove emissioni | Passati i controlli finiti, refinement nativo aperto |
| Range CUDA | Compile sm_90, SASS, registro/shared/local spills, reader gather bounded | Sorgente/host pronti; compile/gather aperti |
| PCS privata | Salt seek nativo identico, codec/hash/pad originali, FFT a blocchi, query replay di tutti gli oracoli | Identità/conti primi oracoli; adapter/kernel completi aperti |
| Memoria/no spill | Tutti i residenti per fase; cap arena; picco allocato/riservato <80 GB; nessuna seconda cache | Piano parziale, trace integrata assente |
| Visite/lavoro | W/A/KV, source-uniformity e confronto completo sui prefissi 1/2/3 | Conteggi parziali, gate fallito |
| Tempo | Census calcolo nativo; upper completo <=50 s, incl. PCG/inferenza/serializzazione | Assente; FFT globale letterale respinta già localmente |
| Riproduzione | SHA pubblicata/pulita, immagine/CLI/prezzo/deadline fissati, input e harness, evidenza recuperabile | Harness/input locali pronti, provisioning non risolto |
| Autorizzazione | Nuovo GO esplicito per workload e costo concreti | Assente |

Non richiedere spesa per misurare una costruzione già incompatibile.
Un esito lento di un microbench componente non prova un lower universale;
un esito veloce non chiude i gate mancanti. Il controllo locale successivo
è l'adapter PCS piccolo con seek dei sali e FFT a blocchi, seguito dal
reader/witness A/KV e dal census PCG. Non si avvia H100 con questi gate
ancora aperti e non si dichiara completato il goal C7.1.
