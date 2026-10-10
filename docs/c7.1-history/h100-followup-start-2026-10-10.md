# C7.1 — avvio del seguito H100, 10 ottobre 2026

Il proprietario autorizza una nuova campagna sul solo pod `z6wx2kkn69eoc0`
per sei ore complessive dall'avvio provider, inclusi trenta minuti di
conservazione e spegnimento. L'istruzione nell'allegato della sessione
sostituisce il vincolo di solo lavoro locale; comprende correzioni,
microbenchmark e trial nuovi nello stesso ambito e termine, senza altro
hardware o estensioni. Base locale pulita `ccbea66b`, branch
`exploration/c71-local-20261010`; nessun commit successivo locale.

La prima query API trova `RUNNING`, uptime 437 s. La query usata per il
guard ricostruisce conservativamente l'avvio come inizio della richiesta
meno uptime e sessanta secondi: **16:27:24,201 UTC**. Fine calcolo
**21:57:24,201 UTC**, guard **22:22:24,201 UTC**, stop provider entro
**22:27:24,201 UTC**, cioè **00:27:24 Italia dell'11 ottobre**.
L'SSH non azzera il tempo. Il guard indipendente è sulla VM locale,
con deadline fissa, query iniziale e retry stop/get fino a `EXITED` con
runtime assente. Va ritirato solo dopo conferma provider; il monitor
dei processi non sostituisce questo controllo.

L'SSH verifica una sola `NVIDIA H100 80GB HBM3`, 81.559 MiB,
driver 580.126.09, UUID `GPU-e05e977b-758d-f3f4-cbe8-5720b83d1ae1`.
L'UUID differisce dalla campagna precedente: si ripete la parità CUDA
della nuova sessione, senza trasferire misure fisiche. `/workspace` è
vuoto; non esiste un packed da riusare sul container. Checkout solo Git
HTTPS dopo preflight; input Γ conservati e verificati, poi nuovi corpi
W sottoposti a hash prima di saltare qualsiasi fase numerica.

Priorità del [seguito locale](local-followup-2026-10-10.md#verifiche-hardware-prioritarie-dopo-il-seguito-locale):
attribuzione dello spike A con W/setup trattenuti e correlazioni fresche;
pool e fill separati sui caller reali; confronto inferenza ottimizzata;
screen della candidata RMS coarser. Γ ammesso resta il riferimento,
geometria A e 512 replay invariati. Nuovo Γ solo dopo tutti i controlli
richiesti; nessun credito da fixture o upper analitici. Prova/verifica
canoniche complete solo con prerequisiti e tempo residuo sufficienti.
Si conservano anche misure negative e ogni run terminale, con journal
nuovi; nessuna correlazione o KV di sessione viene ripresa.

Limiti e conservazione restano quelli del [runbook](../c7.1/runpod-tests.md):
payload 5.905.580.032 B, fisico 6.174.015.488 B, margini globali,
CPU AS64 GiB/CUDA senza cap AS, stop trace bounded, OOM/swap/deadline,
bundle persistente cumulativo 10 GB. Traccia e profiler sono diagnostici
da contabilizzare, senza esenzione aggiuntiva. Evidenze e conclusioni
seguiranno in record nuovi; le fonti storiche restano immutate.
