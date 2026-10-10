# C7.1 — baseline locale dopo la chiusura H100, 10 ottobre 2026

La ricostruzione parte da `072de372a3d1038b037856950bfffb84657920af`,
inizialmente pulito. Non esegue hardware, rete, pesi reali o domini PCS
D34/D35. L'[inventario con hash](../../benchmarks/results/c71-local-baseline-inventory-2026-10-10-072de372a3d1.json)
è uno screening di integrità (`credit:false`): registra `git_dirty:true`
perché le implementazioni locali autorizzate, svolte in parallelo,
erano iniziate prima della verifica. Nessun record storico viene corretto
o sovrascritto. Le istruzioni correnti sono nei cinque documenti attivi.

## Artefatti presenti e riuso verificato

`artifact/c7.1-pod` contiene **3.242 file / 234.830.264 B**, inclusi
manifest e sidecar. Si verificano 54 manifest originali: **3.134 file
manifestati presenti** hanno byte e SHA-256 esatti; quattro file mancanti
sono ritirati dalla [ricevuta dell'8 ottobre](artifact-retention-2026-10-08.md),
con gli stessi hash, dimensioni e provenienza. Non sono corruzioni.
La verifica comprende 31 record pubblici e 932 relativi artefatti,
fra cui i CSV fisici, progressi e observer della campagna e i log RMS.
I digest dei 27 record della campagna sono confrontati con la
[ricevuta finale congelata](../../benchmarks/results/c71-h100-campaign-close-2026-10-10-304e0d74d5a9/final-integrity.json);
gli altri record restano legati al commit sorgente. Non vengono rimossi file.

Gli input selezionati per la H100 sono ancora disponibili e verificati:
candidata, ricevuta Γ, ingest, ledger, piano originale, ricette e tabelle.
La candidata conserva **772 esponenti W / 1.435 esponenti A**; la mappa W
coincide con l'ingest. Il piano originale ha SHA-256
`a26a68972307e17b85086791a1c4870ae66b90a905922472a391267574a8fdf5`.
Le tabelle certificate conservano 24.414.870 B e SHA-256
`052de68a51b02da1b442ed31ce49031630976747cf6605c191672c1e8417d31d`.
Workload, metadati e terminali corrispondono alle identità ammesse.
L'inventario elenca hash e dimensioni degli ingressi senza duplicarne
i contenuti.

Il verificatore storico di Γ viene eseguito sui soli file conservati,
sotto 60 s / AS 2 GiB. Passano nuovamente i cinque controlli delle
ricevute: i tre contesti hanno 150 token, 3.471 sorgenti ciascuno e i
conteggi originali. La [ricevuta ricalcolata](../../benchmarks/results/c71-local-baseline-inventory-2026-10-10-072de372a3d1/gamma-receipt-rechecked.json)
è **byte per byte identica** a quella congelata, SHA-256
`a6d6abe28da2d50629e1e6790d7af76ab58002f0f21aab8b917dab16b0676259`.
Questo verifica il riuso delle evidenze; non ripete calibrazione,
confronto numerico completo o ammissione di una candidata nuova.
Nel report di trace storico il campo superiore
`independent_comparison_complete:false` convive con i campi selezionati
`trace_validation.exact_comparison_complete:true` e
`independent_oracle.complete:true`: la ricevuta ammette Γ controllando
questi ultimi e i rispettivi censimenti. Il record congelato è preservato.

Non sono presenti i corpi degli shard (62.546.338.248 B complessivi),
del packed W (61.394.690.560 B) o della traccia numerica completa
(40.827.296.903 B). Il file più grande nel deposito è una copia delle
tabelle da 24.414.870 B. Si conservano hash e report di quei corpi,
che non consentono di leggerli o ripetere le loro esecuzioni localmente.
Non vengono scaricati. Esistono 28 file ELF ARM64/x86_64 nell'archivio;
l'inventario ne registra architettura e hash senza eseguirli. L'esistenza
di un binario non costituisce verifica di compatibilità o parità CUDA.

La verifica ripetibile, con un output nuovo, è:

```bash
(ulimit -v 2097152; timeout -k 5s 60s python3 \
  benchmarks/results/c71-local-baseline-inventory-2026-10-10-072de372a3d1/verify-retained.py \
  "$PWD" /tmp/c71-retained-inventory-new.json)
```

## Baseline: misure, contatori e schermi

La [chiusura](h100-campaign-close-2026-10-10.md) conserva **zero
certificati accettati**. O=150/300 non iniziano; prova e verifica complete
sono non misurate, mai zero. Gli intervalli completi acquisiti sono:

| Misura | Secondi | Ambito e sovrapposizioni |
|---|---:|---|
| Caricamento W | 61,542960 | Sesto trial; distinto dalla residenza |
| Residenza CUDA W | 22,722726 | Sesto trial; distinta dal commitment |
| Installazione W | 212,418391 | Include PCS W 190,425 s; non si sommano |
| Setup AES V/P | 1.493,833128 / 1.493,832316 | Ruoli simultanei; non si sommano |
| Inferenza O=0 separata | 84,381738 | Nostro esecutore intero esatto, 150 token |
| Preparazione canonica O=0 | 85,020855 | Inferenza e validazione incluse |
| A04 terminale | 780,204680 | Wall fino allo stop; A incompleta a 86/512 gruppi |

Gli **84,382 s riguardano il nostro esecutore intero esatto**. Manca un
confronto sullo stesso workload con un motore di inferenza ottimizzato;
non sono una misura di quanto sia intrinsecamente onerosa l'inferenza
del modello. Il target di risposta 65 s resta non raggiunto.

Lanci, fence, allocazioni, rilasci, zeroing e trasferimenti sono ledger
**cumulativi dall'inizio dell'owner**, non tempi o picchi di una fase.
Il canonico include W, inferenza e replay A nello stesso owner. I conti
per una fase derivano dalla differenza fra suoi confini, quando entrambi
sono disponibili; un solo campione finale non consente tale attribuzione.
`peak_capacity_bytes` è capacità massima contabilizzata, non uso fisico
GPU. RSS, HWM, HBM intera e payload hanno ambiti diversi e non vanno sommati
con massimi presi in momenti differenti.

Gli 844.006.203.160.300 prodotti Fp3 CPU residui, i
998.927.195.904 callback per risposta e le compilazioni RMS 4.293→1.908
sono derivazioni analitiche del [checkpoint RMS](crypto-rms-close-2026-10-09.md).
Le fixture packed con scale nonzero, il primo round e GKR completo ridotto
dimostrano equivalenza nel loro ambito; non forniscono tempi completi per
Γ ammesso o previsioni H100. Rimangono 512 ricostruzioni iniziali A e
almeno 581 scansioni complete prima delle richieste parziali e degli altri
consumer. I timeout RMS/PCS, AES/KV e uncached restano esiti negativi a 60 s.

## Regressione del batching e pista sull'allocatore

Il [prefill ritirato](h100-prefill-2026-10-09.md) passa parità, ma impiega
132,035952 s contro 90,615329 s: **+41,420622 s / +45,71%**. Riduce
di circa 65,98% lanci, fence e allocazioni. I contatori ridotti non
giustificano la selezione né dimostrano la causa della regressione.

La nuova lettura degli observer congelati considera i campioni interni
alla preparazione, stimata da UTC monitor e wall del runner, ed esclude
cinque secondi a entrambi i bordi. Questo allineamento è approssimato;
l'observer campiona ogni cinque secondi e non attribuisce il tempo CPU.

| Schedule | Campioni interni | Wchan del thread principale | Utilizzo GPU osservato |
|---|---:|---|---|
| Scalare | 16 | `0` in 16/16 | 42–49% |
| Batch prompt | 24 | `vm_mmap_pgoff` 9, `__vm_munmap` 10, `0` 5 | 0% in 19/24, poi 10/45/49/46/46% |

I dati motivano un'ipotesi di costo delle allocazioni/mapping e della
durata dei buffer, senza isolare il sito o la durata della causa. La
nuova candidata di riuso di un flag numerico da 256 B mantiene la
schedule scalare e tutti i kernel, controlli, copie e fence necessari:
va valutata sul proprio conteggio e con i caller reali. Non risolve
per deduzione il mapping dei grandi buffer della variante batch.
Reintrodurre il batching richiederà prima attribuzione per sito, taglia
e durata, poi una modifica che risolva la causa osservata e un confronto
a lavoro uguale. Nessun dato corrente lo autorizza come ottimizzazione
selezionata.

## Spike fisico: ciò che i CSV discriminano

Si ricalcolano i due ultimi campioni stabili di
[canonical06](../../benchmarks/results/c71-h100-canonical-06-2026-10-10-47af19bbe888.json)
e [A04](../../benchmarks/results/c71-h100-a-component04-2026-10-10-47af19bbe888.json).

| Campo simultaneo campionato | Canonical06 | A04 |
|---|---:|---:|
| RSS host, invariato nei due campioni | 61.689.729.024 B | 61.606.055.936 B |
| HBM prima dello spike | 67.131.932.672 B | 67.185.410.048 B |
| HBM dopo lo spike | 67.660.414.976 B | 67.719.135.232 B |
| Delta HBM | 528.482.304 B = 504 MiB | 533.725.184 B = 509 MiB |
| Temporanei simultanei finali | 6.560.767.488 B | 6.535.814.656 B |
| Eccedenza sul cap 6.174.015.488 B | 386.752.000 B | 361.799.168 B |

Esenzioni W host/device e swap sono invariati; non sono transizioni W.
La crescita terminale è nella **HBM intera**. L'ultimo progresso registra
capacità native vive 5.281.804.032 / 5.301.060.096 B e massimo nativo
5.436.230.400 B in entrambi i run, ma non è sincronizzato con il campione
terminale. Non si sottrae quel progresso per fingere una misura esatta
della memoria interna al driver. Mancano ID/siti delle allocazioni, cap
libere trattenute e timeline dei kernel/eventi CUDA. La causa può quindi
ancora essere crescita live non osservata, retention dell'allocatore,
stato interno CUDA o un'altra componente device; non è attribuita.

`CUDA_LAUNCH_BLOCKING=1`, code ridotte e connessioni 1/1 **non risolvono**
lo stop: A04 arriva a più gruppi, ma conserva un fallimento fisico.
Questo scarta la configurazione sincrona come rimedio dimostrato;
non esclude da solo un contributo della schedule. A04 omette W commitment,
setup e prova, quindi non misura il picco canonico. SIGKILL non attesta
cleanup dell'owner. La GPU libera dopo lo stop non identifica lo spike.

## Domande prioritarie per hardware futuro, non eseguito

1. **Quale allocazione o evento fa crescere la HBM di circa 0,5 GiB
   durante A?** Usare Γ ammesso, W reale verificata, geometria D34 e
   stessa schedule scalare/code selezionate, con monete fresche dopo
   NoPeek. Conservare la baseline originale. Registrare per alloc/free
   owner timestamp, sequenza, handle/ID, sito/kind, richiesta, allineamento,
   capacità live e capacità trattenuta; includere W, stack/runtime e ogni
   buffer aggiunto dalla misura. Correlare queste righe con stream,
   kernel/memcpy/memset, gruppi A, fence esistenti e campioni HBM/RSS.
   [Nsight Systems](https://docs.nvidia.com/nsight-systems/UserGuide/index.html)
   traccia le allocazioni CUDA esplicite; il residuo driver non si deduce
   dal solo memory graph. [CUPTI](https://docs.nvidia.com/cupti/main/main.html)
   permette la correlazione delle API con attività kernel/trasferimenti.
   Il discriminante è se HBM−somma delle capacità device esplicite cresce
   mentre queste restano stabili, oppure se cresce una capacità posseduta
   identificata. Un componente A può diagnosticare; la conferma con W/setup
   simultaneamente vivi resta necessaria. Conservare i cap originali,
   gli stop fisici e la deadline autorizzata, anche durante la profilazione.

2. **Il riuso verificato del piccolo flag riduce costo API senza aumentare
   il picco fisico o cambiare la numerica?** Confrontare scalare corrente
   e candidata sullo stesso workload, prima con trace alloc/API, poi con
   ripetizioni senza profiler; tenere carico/residenza separati. Misurare
   durata alloc/free, durata fence/copied flags, kernel, contatori, 150 token
   esatti e census simultaneo. Confrontare anche un motore ottimizzato sugli
   stessi prompt e contesti: una traiettoria teacher-forced fissata separa
   il lavoro dal diverso output autoregressivo. Specificare precisione e
   semantica del motore; un motore floating è un riferimento ingegneristico,
   non parità della relazione intera. Arrestare su prima divergenza del
   percorso esatto, overflow, cleanup fallito, cap o deadline.

3. **Le migliori scale alternative preservano calcolo utile e riducono
   il costo RMS/GKR realmente dominante?** La graduatoria e gli obblighi
   delle candidate sono quelli dello screening locale dedicato. Prima di
   una selezione richiedere pesi reali e workload O=0/150/300, confronto
   indipendente, qualità e token secondo criteri espliciti, ricette/tabelle
   certificate, range e tutti i controlli di ammissione. Misurare separatamente
   compilazione, replay Booleano, coefficienti Fp3, callback e PCS; ridurre
   width/depth non riduce automaticamente A o le 512 ricostruzioni.
   Arrestare su degenerazione numerica, non-finiti/overflow, rifiuto del
   compilatore o cap/deadline, conservando l'esito e Γ ammesso come riferimento.

Il piano operativo finale può restringere ulteriormente questi test.
Nessuna voce avvia una campagna o estende autorizzazione, spesa o timeout.
Hash, fixture e profili locali possono verificare identità, conto e parità
ridotta; causa dello spike, guadagno H100, qualità reale e completamento
canonico richiedono le misure hardware o la nuova calibrazione indicate.
