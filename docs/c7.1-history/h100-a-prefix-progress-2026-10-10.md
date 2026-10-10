# H100: tre gruppi A dopo la correzione — 10 ottobre 2026

Il [diagnostico A02](../../benchmarks/results/c71-h100-a-component02-2026-10-10-47af19bbe888.json)
usa checkout pulita `47af19b`, binario Rust `3ea1e4a` e libreria sm_90
`47af19b`, dopo 15/15 parità reali. Pesi packed 0400, Γ e tabelle sono
riusati con identità verificata. Nessun download o ricostruzione degli input.

Caricamento W 61,386 s, residenza nativa 26,347 s, preparazione O=0
85,154 s. A supera il rifiuto precedente e completa tre dei 512 gruppi.
L'ultimo campione A è a 18,035 s dall'inizio di quella fase, con
40.044.279.418 visite sorgente, inclusa parte del quarto gruppo.
Lo stop dopo almeno tre gruppi era dichiarato nel launch prima dell'avvio;
il controller invia SIGTERM al proprio monitor, che termina il figlio.
Wall totale 208,177 s; exit −9, causa `KeyboardInterrupt` nel monitor.
È un arresto diagnostico pianificato, non un timeout o un errore di risorse.

I 1.040 campioni sono stabili, senza errori smaps o swap. Massimo fisico
6.009.748.992 B sotto 6.174.015.488 B; payload 5.554.384.672 B sotto
5.905.580.032 B. Lo stato omette commitment W/setup e non dimostra il picco
canonico. Nessun commitment A completo, prova, verifica o accettazione;
`credit:false`. Monete PCS fresche, nessun PCG o correlazione usata.

La correzione è mantenuta. Il nuovo `canonical-06` parte da W alle
00:40:05 UTC del 10 ottobre, con setup AES/correlazioni/journal freschi,
KV vuoto e lo stesso Γ. Usa anche la coda cGGM differita validata.
Timeout diagnostico 7.056 s, distinto dal target 65 s e limitato dalla
fine calcolo della campagna; nessuna estensione delle otto ore.

Bundle `h100-final-a-component02-20261010T004000Z`, 16 file/249.158 B,
manifest SHA-256 `2e8340b601c4eea02bb13c9fcfe850b1d93819a7007287d3c552a8666d59ce92`.
