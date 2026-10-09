# H100: terzo trial, monitor e riserva iniziale CUDA — 9 ottobre 2026

Il [record terminale canonical-03](../../benchmarks/results/c71-h100-canonical-03-2026-10-09-2a31625f849d.json)
conserva il trial fresco su binario scalare `2a31625` e libreria Tensor `26c4c89`.
Alle 21:33:44 UTC il monitor termina il processo dopo 572,209 s per
`resident W range missing from smaps`. Non è un timeout o una violazione
osservata del cap fisico. Il vecchio monitor non conservava la lettura
fallita: una modifica delle VMA durante la lettura è una possibile causa,
non una diagnosi provata. Il fallimento originale rimane tale.

W PCS termina in 436,687 s, installazione W in 463,597 s; caricamento
packed 66,613 s e residenza device 23,116 s sono separati. Il setup
inizia ma non termina. Non iniziano inferenza, prova o verifica, e nessuno
dei contesti O=0/150/300 è accettato. Entrambi i journal registrano la
capacità bruciata di 70.778.880 correlazioni; non si riprende la sessione.
Il massimo temporaneo stabile campionato è 5.113.933.312 B, su 907 campioni
stabili e due transizioni escluse. Il picco completo resta non dimostrato.

`7f9c812` ammette due sole riletture per campione con copertura W incompleta,
con massimo 64 letture fallite per run. Ogni lettura fallita viene salvata
e sincronizzata in un file privato nuovo. L'esenzione W richiede copertura
completa e contigua e identità del processo invariata; nessuna esenzione
nominale o tolleranza di memoria viene aggiunta. La lettura recuperata
subisce comunque il controllo fisico e non concede credito al picco stabile.
Tre letture consecutive fallite, il limite cumulativo, un errore di formato
o un cambio di identità restano terminali. Passano 35 test locali del monitor,
inclusi sovrapposizione che maschera un buco, conservazione e cap fisico.

Il [probe dello stack](../../benchmarks/results/c71-h100-stack-probe-2026-10-09-2a31625f849d.json)
misura un contesto CUDA vuoto alle 21:38:56 UTC, dopo la fine del trial:
la descrizione originale «durante setup con W residente» era errata ed è
rettificata dal nuovo record, senza alterare lo stdout originale. Richiedere
256 B invece dei 1.024 B iniziali libera 207.618.048 B; ripristinare 1.024 B
restituisce la stessa disponibilità iniziale. Non esegue kernel C7.1 e
non dimostra il risparmio canonico o l'allowance completa.

La build sm_90 precedente dichiara 92 funzioni, stack massimo 216 B e zero
spill. `a32a6c3` imposta e verifica 256 B alla creazione del contesto, prima
dello stream; errore o valore diverso ferma l'owner. Due test Python locali
del runtime nativo passano, inclusi tre casi di errore dell'inizializzazione.
La [API CUDA 12.8.1](https://docs.nvidia.com/cuda/archive/12.8.1/cuda-runtime-api/group__CUDART__DEVICE.html)
descrive una richiesta modificabile dal driver: il controllo legge il valore
effettivo, ma non è un bound dell'intero runtime. Compilazione sm_90, 15 parità
reali, diagnostico numerico e misura fisica della nuova libreria sono richiesti
prima di selezionarla in un nuovo trial; i risultati seguiranno in record nuovi.

È inoltre conservata una deviazione operativa: il commit prefill `3e6c63a`,
già pubblicato via HTTPS, fu anche trasferito come bundle Git via SSH,
contrariamente alla regola attiva di trasporto. Nessuna credenziale fu
trasferita. Il prefill è ritirato; la ricevuta del checkout anonimo HTTPS
`cdd57af` verifica entrambe le revisioni di build e sette file pubblicati.
I successivi aggiornamenti dei sorgenti usano esclusivamente Git HTTPS.
Deadline e guard della campagna rimangono invariati.

La [composizione del traffico](../../benchmarks/results/c71-h100-communication-composition-2026-10-09-a885e07a0ada.json)
somma gli 86.332.473 B realmente scambiati prima del certificato nel primo
trial, il limite inferiore analitico del corpo O=0 (47.841.180 B) e 753 B
di framing/completion mancanti. Il risultato è **134.174.406 B** nei due
sensi, già superiore al target iniziale di 130 MB. Include la distribuzione
pubblica come richiesto dalle specifiche; il solo verso al verificatore
ha limite inferiore 126.639.876 B e non basta a stabilire quel superamento.
I corpi delle continuazioni superano già 40 MB. È un risultato composto
misurato/analitico, non un certificato completo ottenuto né un nuovo cap.
