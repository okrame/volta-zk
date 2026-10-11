# Seguito RMS byte: piano pronto per nuova autorizzazione — 11 ottobre 2026

Obiettivo invariato: primo certificato canonico O=0 verificato dal DV
originale e conservato immediatamente; poi O=150/300 nella stessa nuova
sessione. Zero certificati disponibili. Il pod è fermo, la finestra
precedente è scaduta e questo piano non avvia né autorizza hardware.

## Evidenze e decisione

Il [confronto precedente](h100-certificates-rms-shared-cache-2026-10-11.md)
misura 158,589 s con cache/gate su 511 celle sintetiche vive e tutte le
159 ricette. L'endpoint byte conserva 30.985.128 letture dei frame.
La [contrazione byte bounded](local-byte-streamed-contraction-2026-10-11.md)
ha parità locale e limite di capacità, ma manca la stessa misura completa
ridotta sul pod. Il [ledger simultaneo](local-rms-candidate-ledger-2026-10-11.md)
conta le tre candidate; O=300 resta oltre cap nella query PCS.

L'ispezione di `cuda/c71_fp3.cuh`, `cuda/c71_linear_native.cuh` e del
runtime comune conferma aritmetica MAC u³=2 e primitive di riduzione,
ma nessun consumer RMS GKR già utilizzabile. Un backend per il solo
core, con righe folded caricate dalla CPU, introdurrebbe trasferimenti
aggiuntivi; replay e fold devono rientrare nella sua valutazione.
Non viene introdotto un kernel senza un caller utile al dominio intero.
Prima si misura la candidata completa già implementata e si distingue
il residuo di cella/replay dall'endpoint byte. Nessun limite temporale
canonico è ricavato dal numero analitico di prodotti.

Il binario di test aggiunge tre cronometri monotoni non sovrapposti:

- cella: costruzione replay/piano, rigenerazione/fold, coefficienti,
  cache, FS e MAC per ogni profondità;
- indice: costruzione edge, due riduzioni, FS/MAC e nuovi pesi;
- byte: wrapper dell'endpoint, supporto, LUT, contrazione, FS/MAC.

La differenza rispetto a `prove_ns` è `other_prover`: bind, preparazione,
prodotti GKR, contatori, teardown e altri intervalli non classificati.
La somma deve coincidere con il tempo totale dopo l'aggiunta del residuo.
Sono contatori `cfg(test)`, assenti dalle build di protocollo. Nessun
nuovo heap di misura, modifica di wire, coin o premesse crittografiche.
L'effetto sul timing del binario di test deve restare nel confronto.

## Campagna proposta, non avviata

Solo pod `z6wx2kkn69eoc0` e H100 UUID
`GPU-e05e977b-758d-f3f4-cbe8-5720b83d1ae1`. Nuova autorizzazione proposta:
massimo otto ore dall'avvio provider, inclusi trenta minuti riservati
alla conservazione e allo stop. Identificatore, directory, guard e
deadline nuovi; nessun riuso dell'avvio, guard o stato terminale precedente.
Stessi cap: CPU AS64 GiB, fisico 6.174.015.488 B per il diagnostico senza
esenzione W, un worker. Nessun profiler o nuovo setup AES in questa misura.
La fixture gira sulla CPU del pod; non è esecuzione CUDA del core.

Verificare identità hardware, GPU idle, accesso all'arresto provider,
guard indipendente e SHA pulita prima della build. Riutilizzare la
procedura già validata nel bundle privato `certificates-rms-shared02-20261011/run.py`,
aggiornando SHA, directory, deadline e le varianti sotto; non eseguire
quel launcher storico, che contiene deadline scadute. Una build mirata
con Rust 1.96.1, opt2, un job, deadline 900 s; monitor fisico invariato.
Conservare hash del nuovo binario e verificare le ricette contro
`benchmarks/results/c71-certificates-rms-shared-support-local-2026-10-11-fe5f9d65/c71-rms-shared-recipes-20261011.json`.

Il filtro è `c71_rms_pinned_representative_full_depth_benchmark`, con
`--ignored --nocapture --test-threads=1`, 512 celle, 159 programmi,
99 profondità e 9.919 correlazioni ideali. Eseguire due coppie, ordine
AB poi BA, stesso binario e seed della fixture, timeout 600 s per prova:

| Variabile | A: cache/gate | B: cache/gate/byte |
|---|---:|---:|
| `C71_RMS_BENCH_CELLS` | 512 | 512 |
| `C71_RMS_BENCH_CACHE_BYTES` | 16777216 | 16777216 |
| `C71_RMS_BENCH_SHARED_GATES` | 1 | 1 |
| `C71_RMS_BENCH_BYTE_CONTRACTED` | 0 | 1 |

`C71_RMS_BENCH_RECIPES` punta al JSON pinned sopra. Usare il monitor
`scripts/c71_campaign_measure.py --mode component`, deadline assoluta
nuova e riserva 1800 s. Prima di ogni comando deve restare tutto il suo
timeout più tempo sufficiente alla conservazione; nessuna estensione
a seguito di failure. Controllare GPU idle prima/dopo ogni prova.

Confrontare `phase_ns`, wall, RSS/fisico, campioni incompleti, frame,
prodotti/fold/capacità e `wire_bytes/wire_blake3`. Richiedere tutte le
profondità, FS/MAC originali, consumo completo e wire uguale fra varianti.
Atteso dal precedente binario: 320.320 B e BLAKE3
`8782b92eb0afecba42a6aeac830933daba5e401c94c06d7b59b96cbaabdad57c`.
Un mismatch, timeout o errore resta un risultato negativo, senza
promuovere parità parziali o ricostruire certificati da hash.

La misura non include statistic caller, modello, PCS o AES. Dopo il
confronto, risolvere il residuo effettivo e verificare backend/capacità
prima di selezionare le candidate. Il runner canonico senza profiler
parte soltanto con impedimenti pertinenti chiusi e tempo residuo utile;
nuovi O=0, journal, KV e correlazioni AES, mai resume terminale.
Conservare subito response/acceptance O=0; O=150/300 solo se la stessa
sessione può continuare rispettando anche il cap ora negativo a O=300.
Se manca una soluzione eseguibile nella finestra, conservare e spegnere
anticipatamente. Target 65 s e certificato valido restano distinti.
