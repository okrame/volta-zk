# C7.1 — primo commitment A completo del modello, 11 ottobre 2026

Il [record del trial](../../benchmarks/results/c71-certificates-a-vmm-pool01-2026-10-11-6ccb54a1.json)
conserva il completamento del componente iniziale A a O=0: **512/512
gruppi**, geometria originale, uscita zero e nessun arresto del monitor.
La libreria combina backing VMM differito e pool stream-ordered da 128 MiB
limitato ad A, dopo le [parità H100](../../benchmarks/results/c71-certificates-vmm-pool-preflight-2026-10-11-6ccb54a1.json).
SHA sorgente pulita `6ccb54a1621649f6483ab58707bd24dec6a44d3a`; il binario
Rust è riusato da `abf57c4a`, senza differenze di produzione pertinenti ad A.
Hash e comandi sono nella provenienza del record.

| Misura | Risultato |
|---|---:|
| Commitment A completo | 3.408,761768098 s |
| Preparazione, inclusa inferenza | 78,055591431 s |
| Inferenza, sottointervallo della preparazione | 77,987777835 s |
| Intero processo monitorato, incluso caricamento | 4.158,144197788 s |
| Massimo fisico temporaneo campionato | 5.861.006.848 B |
| Cap fisico temporaneo | 6.174.015.488 B |
| Payload congiunto massimo osservato | 5.435.740.354 B |
| Cap payload | 5.905.580.032 B |
| Capacità native massima | 5.189.054.976 B |
| Campioni / incompleti / failure smaps | 20.746 / 6 / 0 |
| Allocazioni e rilasci finali | 18.706.360 / 18.706.360 |

Il pool termina con fence e verifica reserved/used vuoti prima della
pubblicazione della root. Cleanup finale: arena, capacità live, logical e W
zero, `cleanup_failed:0`; GPU a 0 MiB senza processi alle 12:40:40 UTC
(epoch `1791722440.2974446`). L’owner resta 50.880 B. La riserva del file
trace da 16 MiB è inclusa nel monitor, senza aumento dei cap. I limiti CPU
AS 64 GiB e CUDA senza AS sono conservati nel comando e nel monitor.

L’[analisi dei gruppi](../../benchmarks/results/c71-certificates-a-vmm-pool-analysis-2026-10-11-6ccb54a1/files.json)
usa solo intervalli completi di raccolta interni ai confini CLOCK_MONOTONIC
del gruppo, inclusa l’incertezza dell’anchor di 345 ns. Tutti i 512 gruppi
hanno campioni interni; nessun gruppo parziale. Minimo/mediana/massimo:
6,416220 / 6,563102 / 13,492796 s; somma 3.408,007972 s. La differenza dal
commitment include lavoro fuori dai confini di gruppo. Sono conservati
helper e autocontrolli su intervalli attraversati, letture smaps recuperate,
prefissi non contigui e confini invertiti. Il confronto con i negativi
precedenti non è una coppia controllata né attribuisce causalmente il
rallentamento legacy: solo pool arrivava a 82 gruppi prima dello stop
fisico; VMM senza pool fu interrotto a 14 per ritmo insufficiente.

Il bundle privato verificato è
`artifact/c7.1-pod/certificates-a-vmm-pool01-20261011T124500Z`:
16 file, 13.206.194 B, manifest SHA-256
`6126d27301e2645d4eaaa15ee907e590d889c90daad856ca0d9c48d904ce86ae`.
L’etichetta della directory è un identificatore; tempi effettivi nel record.

**Una root A del modello completata, zero certificati generati o verificati.**
Il componente omette W PCS, setup AES, proof body, verifica designata,
accettazione durevole e continuazioni. Il runner non esporta i byte della
root di componente e nessuno stato viene importato in un nuovo trial.
Il risultato non dimostra il picco fisico istantaneo, l’allowance del runner
completo o il target 65 s. Γ originale resta ammesso e invariato; nessuna
nuova premessa formale è scaricata. La contabilità generale O=300 della
variante resta 29.066.098 B oltre payload. La misura RMS sulle 159 ricette
è il prossimo controllo pertinente; la variante resta diagnostica.
