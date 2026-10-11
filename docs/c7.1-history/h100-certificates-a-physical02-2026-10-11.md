# C7.1 — spike dopo free, stack invariato, 11 ottobre 2026

Il [secondo record](../../benchmarks/results/c71-certificates-a-physical02-2026-10-11-4de3e531.json)
conserva un nuovo O=0 da SHA pulita `4de3e531`, parità del diagnostico e
teardown. Il monitor ferma il componente a 390,190 s, **15/512 gruppi**,
campione fisico 6.487.887.360 B contro 6.174.015.488 B, inclusa la riserva
cache file. Payload massimo osservato 5.554.384.905 B. Zero A/root completi
e zero certificati; Γ originale invariato.

L’evento 441 mostra la crescita subito dopo `c71_range_release`/`cudaFree`
di un buffer I64 da 4.915.200 B. Il limite CUDA dello stack rimane **256 B**
in tutti gli eventi registrati, compreso lo spike. Ciò giustifica un
esperimento sul percorso dell’allocatore, senza identificare internals
del driver né escludere altra memoria locale. GPU idle dopo il teardown.

La nuova variante `C71_ASYNC_ALLOCATOR_EXPERIMENT`, compilabile solo con
traccia fisica bounded, usa `cudaMallocFromPoolAsync` per i temporanei.
W resta nella sua allocazione originale. Il pool del device ha soglia
di rilascio zero, verificata; dopo ogni free viene richiesto trim a zero.
I fence originali rimangono: la [documentazione NVIDIA](https://developer.nvidia.com/blog/using-cuda-stream-ordered-memory-allocator-part-2/)
ammette `cudaFree` su memoria del pool se gli accessi sono già completati
da sincronizzazione esplicita. Se il fence CUDA di cleanup fallisce, i
buffer del pool conservano debito e non vengono liberati anticipatamente;
un errore del logger da solo non impedisce il drain/free native.

L’owner sperimentale è 42.160 B. Una riserva fissa **64 MiB viene addebitata
nel payload prima dell’uso del pool**, oltre a tutti i buffer logici.
Ogni confine owner controlla `reserved <= arena + 64 MiB`, anche prima
dell’arm della traccia; registra used/reserved e massimo slack osservato.
La riserva viene restituita solo dopo trim, pool vuoto e arena vuota.
Query, trim o free incerti mantengono il debito. Cap payload e fisico
rimangono invariati. I sette scenari del driver simulato coprono il
percorso valido, riserva negata, allocazione/query/trim/fence falliti e
superamento del limite cache; non sono evidenza hardware.

**La variante non è selezionata per il protocollo completo.** La riserva
permanente di 64 MiB supera il margine del massimo nominato del ledger
generale: serve ridurla o dimostrarne un lifetime distinto prima della
selezione canonica. Il componente A ha un margine diverso, controllato
dal medesimo counter e monitor. Nessun risultato dell’esperimento è
ancora disponibile; non si aumenta alcun cap per farlo passare.
