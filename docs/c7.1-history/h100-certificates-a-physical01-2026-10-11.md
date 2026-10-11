# C7.1 — spike dopo fence, 11 ottobre 2026

Il [record](../../benchmarks/results/c71-certificates-a-physical01-2026-10-11-85b8592c.json)
conserva il nuovo componente A O=0, con W e Γ originali, senza PCS W o
setup AES, partito da SHA pulita `85b8592c`. Il timeout predefinito è
1.800 s; il monitor ferma prima il processo, a 473,380 s, per cap fisico.
Sono completi **41/512 gruppi**, nessun A/root e nessun certificato.

Picco fisico campionato **6.530.682.368 B**, inclusi 16 MiB riservati alla
cache del file, contro 6.174.015.488 B. Il massimo payload osservato resta
5.554.384.869 B, senza aumento del massimo native. La traccia registra
650 eventi in 233.753 B, sotto il cap di 16 MiB.

Il primo overhead CUDA sopra 600 MB compare nell’evento 649, dopo una
fence dello stream: CUDA usata 67.626.270.720 B, W 61.394.690.560 B,
arena 5.246.892.544 B, differenza **984.687.616 B**. Gli eventi immediatamente
precedenti registrati includono free di buffer I64 da 180.224 B. La
riduzione omette variazioni inferiori a 16 MiB: non identifica ancora
il chiamante/kernel né prova che la free causi lo spike. Non c’è credito
di allowance. Dopo lo stop, GPU 0 MiB e nessuna applicazione compute.

La libreria corrente passa tutti i 16 filtri H100. Il primo filtro della
libreria diagnostica completa un owner e fallisce all’apertura esclusiva
della stessa traccia per un secondo owner: negativo conservato, non
errore numerico. Il filtro di trasformazione a owner singolo e il programma
nonlineare passano separatamente. Nessuna parità completa è attribuita alla
sola diagnostica. I kernel numerici e il protocollo rimangono invariati.

Il nuovo diagnostico registra il chiamante della fence, la riga sorgente
e `cudaLimitStackSize`, per distinguere crescita dello stack da altra
memoria del driver. Il record bounded passa da 512 a 768 B; l’owner resta
42.136 B e il cap file 16 MiB. Il test locale verifica l’attribuzione di
una crescita simulata a `dense_complete`, più query memoria/stack e
scrittura fallite con cleanup. Questa nuova misura resta da eseguire.
