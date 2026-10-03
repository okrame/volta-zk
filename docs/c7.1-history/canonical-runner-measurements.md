# Strumentazione del runner canonico CPU — 3 ottobre 2026

Checkpoint di lavoro locale a partire dal
[riferimento canonico](../../benchmarks/results/c71-canonical-reference-local-2026-10-03-dfb0867c6010.json).
Le istruzioni correnti restano nei [cinque documenti attivi](../c7.1/design.md).
Il [record sulla revisione pulita](../../benchmarks/results/c71-runner-measurements-local-2026-10-03-187a0b9dc9ce.json)
conserva 9 test Rust, 10 Python, due rifiuti CLI attesi, build e lint,
oltre ai fallimenti di compilazione/sandbox separati dai risultati passati.

Il runner precedente escludeva dal timer la lettura iniziale di Γ e
condivideva profili/tabelle/root con V fuori dal trasporto contato. Il
runner ora trasmette questi dati e ricompila dal lato V, conta le richieste
e separa traffico di installazione, Seed6 e risposte. Distribuzione e setup
sono addebitati interamente alla prima risposta. I codec esistenti dei
certificati, i messaggi crittografici e l'ordine dei MAC restano quelli B12.

Le misure wall distinguono i ruoli e le fasi e conservano intervalli
incompleti dopo errore. Non sommano tempi concorrenti. Il preparatore
attuale fonde inferenza, istogrammi e checkpoint: restano sconosciuti i
tempi separati T_inference/T_proof_only. La misura dopo la preparazione
ha quindi un nome distinto, senza attribuire lavoro gratuito alla prova.
Anche CPU-time, picchi per ruolo, allocazioni/capacità trattenute e HBM
rimangono aperti. Il report su errore conserva soltanto nomi di fasi,
tempi, byte e RSS del processo, senza motivi privati del rifiuto.

Il test socket usa tre corpi di 3/4/5 byte: verifica contatori, framing e
completamento, non certificati o accettazioni del registro crittografico.
I test dei cap respingono lunghezze errate prima di leggere il corpo;
gli I/O incompleti conservano soltanto il numero di byte effettivi.
Non sono stati scaricati pesi, avviate GPU, creati pod o sostenute spese.

L'ispezione di `Code::commit`, `Tree::commit` e della configurazione B12
accerta che il runner usa ancora coset da 256 righe e un limite di altezza
2^18. W/D35 e A/D34 richiedono 2^32 e 2^31 righe: il commitment iniziale
canonico è quindi rifiutato prima di qualsiasi certificato. Non è stato
eseguito il dominio grande per verificarlo. Il prossimo collegamento deve
implementare lo schedule canonico e i suoi workspace, non solo alzare il cap.

Restano locali il getter canonico a 512 ricostruzioni, il rimpiazzo dei
workspace densi, il collegamento CUDA esatto, la partizione completa delle
misure, il conto fisico simultaneo e la validazione dell'intera composizione.
Non sono dipendenze risolvibili soltanto con H100. Dati reali/calibrazione e
misure H100 richiedono inoltre autorizzazione; il provider conserva l'hard
stop sulla deadline/controllo di spesa. Rimangono zero certificati canonici
acquisiti, il superamento analitico di 40 MB nelle continuazioni e gli
obblighi aperti della composizione Seed6.
