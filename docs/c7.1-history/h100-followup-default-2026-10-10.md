# C7.1 — default canonico: stop fisico al gruppo A 116

[Record pubblico](../../benchmarks/results/c71-h100-followup-default-2026-10-10-a77c31f98de8.json),
checkout iniziale pulito `a77c31f9`, runner `cfc04b6f`, libreria default
pool/fill `b7c6d0ac`, senza logger o profiler. W/Γ verificati riusati,
nuova sessione AES, nessuna calibrazione del riferimento.

Completi installazione (212,262 s), setup AES (1.486,604 s), preparazione
O=0 (77,123 s) e 116 dei 512 gruppi A. Wall totale 2.701,496 s;
stop imposto dal monitor, exit −9. Temporanei fisici campionati
6.545.690.112 B oltre 6.174.015.488 B; picco payload osservato
5.632.780.867 B, sotto 5.905.580.032 B. Zero certificati, nessun A completo,
O=150/300 non iniziati. Il progresso oltre 35 gruppi non risolve lo spike.

Gli ultimi due campioni conservano lo stesso RSS host: GPU intera cresce
di 535.822.336 B, **511 MiB**. Il massimo nominato native rimane
66.830.920.960 B, W inclusa. La GPU al picco è 67.645.734.912 B:
almeno 814.813.952 B sono fuori da quel massimo nominato. Le capacità
nominate da sole non spiegano il picco. I checkpoint asincroni e NVML
non identificano una specifica allocazione, kernel, cache o leak;
attribuzione completa e timeline CUDA restano aperte. Il requisito fisico
non è soddisfatto su questo prefisso; nessun credito di allowance completa.

Ricompilazione CPU dei programmi RMS reali: 159/91 programmi per Γ
ammesso/coarser, metadati esattamente uguali ai compiler originali congelati.
Somme del solo possesso dei programmi 457.634.736/260.594.224 B;
batch CLI 2,804/1,613 s. Serializzazione inclusa, setup AES concorrente,
un solo thread e AS child più stretto di 2 GiB. Non sono tempi del caller
completo né picchi simultanei; qualità, replay/GKR/PCS della candidata
restano da misurare.

Il probe originale di stop Nsight controllava il target ma lasciava
l'agente; ricevuta e correzione sono entrambe preservate. Il successivo
`nsys-owned-stop04` verifica target e agente terminati, sette identità
contate, CPU AS 64 GiB. Il nuovo `canonical-profile05` usa subreaper,
file/correlazioni nuovi e finestra dopo 113 fino a 117 gruppi; arming 114.
CPU wrapper a 64 GiB, limite rimosso solo nel figlio CUDA. Nessun
allentamento di cap o deadline; strumenti e agenti restano nel census.

Bundle privato verificato
`artifact/c7.1-pod/h100-followup-default-20261010T192300Z`: 289 file,
7.475.813 B, manifest
`05d77bfa2388f210e28bd6ff01a06b58a41ec4869ca3a76dc1c4f627ee1a4210`.
Contiene anche il trial profiler interrotto nel caricamento e i compiler.
Tabelle coarser byte-identiche al bundle Γ: generator/input-check e hash
conservati; il corpo duplicato non è esportato. Manifest precedenti intatti.
