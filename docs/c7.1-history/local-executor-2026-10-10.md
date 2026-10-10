# C7.1 — flag numerico riusabile e ipotesi dell'esecutore, 10 ottobre 2026

## Decisione e ambito

Il common owner conserva un solo flag di errore da 4 B, capacità CUDA
allineata **256 B**, per i caller numerici sincroni. Prima di ogni chiamata
lo azzera sullo stesso stream; dopo i kernel copia gli stessi 4 B e applica
lo stesso fence, controlla l'errore e solo allora pubblica gli output.
Il flag resta privato e addebitato fino al `close`. La candidata riduce il
churn di `cudaMalloc`/`cudaFree`; nessun tempo CUDA nuovo è disponibile.

La modifica è nel
[runtime](../../cuda/c71_range_runtime.cpp), verificata con
[driver differito e UBSan](../../tests/c71_range_runtime_host.cpp).
Riguarda product, RNE, pointwise, RMS, QK, PV, softmax, seal degli istogrammi,
lookup, RoPE e argmax. L'embedding resta la copia D2D degli stessi W.
I flag dei consumer PCS e delle finestre byte restano dedicati: possono
accumulare un errore su più chiamate mentre i producer usano lo stesso owner.
Anche W/compare PCS sincroni conservano la route precedente per limitare la
modifica e il confronto hardware al solo costo dei producer.

Le guardie ABI/owner, forma, span e copertura precedono le operazioni come
prima. Non cambiano Γ, valori raw/RNE, ordine, KV, NoPeek, monete, MAC
originali, PCG AES o fail-closed. Non cambiano kernel, byte copiati,
sincronizzazioni necessarie, ricostruzioni A, dimensioni A o piano PCS.
Non sono introdotte prove/PCS per token. La parità CUDA reale della nuova
libreria resta da acquisire; il driver simulato non la dimostra.

## Conto simultaneo e regressioni

`sizeof(C71RangeContext)` misura **42.096 B**, contro 42.088 B della
versione precedente: il nuovo handle costa **8 B host**. Il pool usa **una
delle 512 entry**, senza aumentare la tabella. Le altre capacità vive e il
limite di entry restano controllati prima dell'allocazione. La prenotazione
device entra nel callback di contabilità comune, in `arena_bytes`,
`live_capacity_bytes` e picchi; rilasciare tutti i buffer pubblici lascia
ancora **256 B** vivi fino al cleanup. Non è un rilascio logico e non è
coperto gratuitamente dalla riserva del runtime.

Il marker `C71_SYNC_ERROR_FLAG_REUSE` permette al ledger nuovo di usare
owner 42.096 B e aggiungere conservativamente 256 B in tutte le fasi con
owner vivo, ritirandoli solo dopo cleanup. Non si sottraggono i flag già
compresi negli upper storici del replay. I record vecchi e i loro manifest
restano immutati. Le aspettative delle fixture Rust sui residui prima del
`close` sono aggiornate da zero a 256 B; gli output numerici attesi restano
gli stessi. Il contatore `releases` ora include anche le free riuscite dei
buffer durante `close`; in precedenza quelle free fisiche mancavano nel
contatore finale. Le free fallite non lo incrementano. Questo corregge
la telemetria del cleanup, senza cambiare la sua schedule.

La fixture ridotta ripete **32** pointwise sui medesimi otto valori,
confrontando ogni raw esatto. Misura **una sola allocazione** del flag;
il percorso precedente ne richiedeva una per chiamata. Restano **32 fence
di completamento** e **128 B D2H del flag**, più i download espliciti usati
dal test per osservare i risultati. Il driver avvelena il word conservato
fra chiamate: il reset sullo stream è verificato anche quando non c'è una
nuova allocazione.

Le regressioni controllano launch/fence/flag terminali, output non leggibili
su errore, assenza di nuovo lavoro dopo stop, rifiuto del budget prima del
launch, handle del pool privato e cleanup. Un errore sticky di una finestra
byte sopravvive a un producer numerico riuscito fra scatter e seal. La free
fallita di un flag dedicato conserva il debito e non viene ritentata. Due
regressioni isolate verificano anche il reset CUDA fallito del pool già
caldo, prima di un nuovo launch/copia, e la free fallita del pool durante
`close`: stop sticky, 256 B ancora addebitati e una allocazione non
rilasciata nel receipt finale. Ogni cleanup riuscito confronta ora anche
`allocations == releases` dopo le free finali.

Il primo test di sviluppo fallisce su un'aspettativa obsoleta del residuo
nell'embedding: `live_capacity_bytes==0`. Dopo averla aggiornata a 256 B,
entrambi i test Python passano sotto 60 s / 2 GiB AS. La compilazione C++
della fixture usa UBSan e un driver differito, senza CUDA. Sul sorgente
pulito `102ecf02ab98` passano **2/2 test**, wall del wrapper **14,352 s**,
RSS massimo **338.870.272 B**, con i limiti 60 s / 2 GiB AS e un worker.
Il fallimento e il successivo controllo sono conservati nelle nuove
evidenze, senza riqualificare il primo esito come pass. I controlli puliti
e i loro digest sono nel
[record conclusivo](../../benchmarks/results/c71-local-exploration-2026-10-10-f71a12519ad9.json).

La regressione Rust `c71_canonical_device_replay_original_rows_windows_and_failure`
sul sorgente pulito `102ecf02ab98` fallisce inizialmente: 25.567.232 B
contro un'aspettativa di 25.566.976 B, differenza esatta 256 B. È una
fixture che installa tables/cuts e costruisce `Session` direttamente,
senza eseguire l'inferenza iniziale: il pool nasce alla prima scan. Nel
caller reale `Session::build` lo ha già inizializzato prima della PCS.
La correzione delle sole aspettative distingue la prima scan fredda
(+256 B) dalla seconda scan numerica già presente, che deve conservare
lo stesso totale vivo senza ulteriore crescita. La parità numerica e le
guardie di produzione restano inalterate; failure e retest hanno receipt
separati nel record conclusivo.

Per isolare il confronto di contatori, il piccolo harness
`c71-executor-flag-census.cpp` collega lo stesso driver differito e ripete
le stesse 32 chiamate pointwise, con gli stessi otto valori e gli stessi
read/release, prima con l'owner `072de372` poi con la candidata. Le
misure nei due receipt sono:

| Contatore del componente ridotto | Baseline | Candidata |
|---|---:|---:|
| Allocazioni del solo flag | 32 | 1 |
| Release del flag prima di close | 32 | 0 |
| Capacità device dopo retirement degli output/input, prima di close | 0 B | 256 B |
| Owner host | 42.088 B | 42.096 B |
| Kernel | 32 | 32 |
| Fence con osservazione e release degli output incluse | 96 | 96 |
| D2H con osservazione raw inclusa | 2.176 B | 2.176 B |
| Azzeramento dei flag | 128 B | 128 B |

Il record conclusivo conserva entrambi i receipt osservati
e include sorgente, comandi e digest del confronto. I tempi del driver
CPU simulato non sono stime di accelerazione H100.

## Census analitico sul Γ ammesso

[c71_executor_profile.py](../../scripts/c71_executor_profile.py) legge solo
il piano pubblico conservato, SHA-256
`a26a68972307e17b85086791a1c4870ae66b90a905922472a391267574a8fdf5`,
4.029.315 B, verificato dal
[nuovo inventario](../../benchmarks/results/c71-local-baseline-inventory-2026-10-10-072de372a3d1.json).
Le regole provengono da `rows_at_token`, `batches`, `scan_inner`,
`padding_word` e dai caller reali `produce_native`. Non esegue W, replay,
compiler, provider o kernel e non legge tracce private.

Per ciascuno dei contesti O=0/150/300, la generazione scalare dei 150 token
usa **1.185.770 flag numerici**, inclusi i 121 seal degli istogrammi.
QK, softmax e RNE degli score usano 32 chiamate per token; logits,
RNE finale, softcap e argmax ne usano 50 complessive, la Norm finale 149.
Le **1.185.820** launch analitiche aggiungono il secondo kernel delle 50
argmax; **4.743.280 B D2H** sono 4 B per flag più 4 B per token scelto.
Entrambi coincidono con i contatori cumulativi del
[diagnostico H100 scalare](../../benchmarks/results/c71-h100-inference-01-2026-10-09-2a31625f849d.json),
senza trasformarli in misure di tempo per operatore.

Con owner fresco il pool elimina analiticamente **1.185.769** coppie
allocazione/free del flag. A parità del resto delle allocazioni, le
3.641.220 allocazioni native del diagnostico scalare diventerebbero
**2.455.451**, riduzione **32,5652%**: è una previsione di contatore,
non una misura della nuova inferenza né una percentuale di tempo risparmiato.

Una scan che richiede tutte le sorgenti A usa **13.667** flag:
7.786 chiamate dei producer nel DAG pruned, 121 seal e 5.760 pointwise per
il padding i64 raw-score/E/Z delle 32 teste nei 60 layer. I 302 ID frozen
sono 61 checkpoint, 120 K/V e 121 istogrammi. Gli altri C/S RMS con più di
150 righe non sono padding attention. Le 512 ricostruzioni iniziali A
usano quindi **6.997.504 flag** analitici; il pool già caldo dalla
preparazione elimina tutte quelle allocazioni del flag. Gli altri
consumer parziali hanno DAG selezionati propri: non si attribuisce loro
questo conteggio. La larghezza delle colonne cresce con O, mentre questo
numero di chiamate rimane uguale.

## Ipotesi aperte e prossime misure hardware

La riduzione di churn è verificata nella fixture e motivata dal caller.
Il suo contributo al wall H100 è aperto. Gli
[84,382 s](h100-campaign-close-2026-10-10.md) misurano il nostro esecutore
intero esatto, senza confronto con un motore di inferenza ottimizzato sullo
stesso workload. Il prompt in batch resta
[ritirato](h100-prefill-2026-10-09.md): meno contatori non provano un guadagno.
Le attese di mapping/munmap durante quel run sono una pista, senza
attribuzione delle allocazioni. Il piccolo pool dei flag non dimostra
di correggere i temporanei grandi o la regressione del prefill.

Lo [spike finale di 509 MiB](h100-a-blocking-terminal-2026-10-10.md) resta
non attribuito anche con code ridotte e lanci sincroni. Non è spiegato
dai soli 256 B del pool. Il massimo di 131.072.000 B al RNE finale è un
subtotal analitico; non prova l'origine di una crescita runtime più grande.
Buffer grandi riusabili, fusioni e CUDA Graphs richiedono prima una misura
che separi costo API, esecuzione kernel e allocazioni driver. Un pool
generico tratterrebbe tutte le capacità e potrebbe peggiorare proprio la
fase PCS A; per questo qui è limitato al flag numerico sincrono.

1. **Quanto costa il churn dei flag sulla H100?** Dopo parità reale di tutti
   i producer, confronto scalare originale/pool sugli stessi Γ, W e token
   pinned. Misurare wall di inferenza separato da caricamento/residenza,
   conteggi differenziali, durata CPU CUDA API `cudaMalloc/cudaFree`, kernel
   e fence, GPU idle, capacità vive e fisiche simultanee. Il risultato
   discriminante è la riduzione prevista di alloc/free con stessi kernel,
   fence, byte, originali e token, poi l'effetto sul wall. Fermare su
   qualsiasi mismatch, errore CUDA/budget, cap fisico o deadline autorizzata.
2. **Quale evento provoca lo spike A?** Profilare un diagnostico A separato
   per attribuzione, con CUPTI/Nsight Systems o una traccia equivalente di
   runtime/driver alloc/free, stream/eventi, lifetime degli output, byte e
   census applicativo. Correlare gli ultimi eventi con HBM/RSS/cgroup
   simultanei; distinguere output RNE, allocator e runtime. Una nuova
   configurazione di code senza questa traccia non risponde alla domanda.
   Solo dopo attribuzione ripetere lo stato canonico W/setup, perché il
   diagnostico A lo omette. Mantenere i cap e deadline, preservare lo stop.

Nessuna fase hardware è eseguita in questo studio; non si trasferiscono
tempi CPU o driver simulato alla H100 e non si cambia l'ammissione Γ.
