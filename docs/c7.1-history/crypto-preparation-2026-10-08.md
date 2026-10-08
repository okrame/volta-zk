# Preparazione del percorso crittografico H100 — 8 ottobre 2026

Istruzione corrente del proprietario: goal locale per l'intero percorso
canonico C7.1 H100 80 GB, con protocollo/numerica/sicurezza invariati.
Si conclude prima della campagna H100; hardware e durata richiedono una
nuova autorizzazione. Baseline richiesta `9033c64`, checkout iniziale
`47135ca` (sole istruzioni documentali aggiuntive), branch locale
`task/c71-h100-crypto-20261008`.

La diagnostica del 7 ottobre è incompleta dopo 2.461,09 s nel commitment
W, prima di setup e risposte. Γ è ammesso sul workload pinned. I record
originali rimangono immutati. Telemetria e buffering non toccano le
identità numeriche pertinenti a Γ; successivi cambiamenti dei producer
richiedono un nuovo controllo documentato del loro impatto.

Il commit `04ab8ed` integra buffer XOF sequenziale da 4 KiB e JSONL
privato durevole. Motivo: startup sali senza visibilità e fill da otto
byte ripetuti; si riusano BLAKE3, sampler, metriche e census esistenti,
senza dipendenze. I seek devono usare il cursore logico dopo prefetch;
le foglie strided non allocano buffer, mentre gli scan e i sottoalberi
sequenziali ne usano uno. Il log registra fasi/lavoro/trasferimenti/memoria
anche prima di un timeout, senza aggiunte al transcript o resume.

[Evidenza locale pulita](../../benchmarks/results/c71-crypto-preparation-local-2026-10-08-04ab8ed1c4ce.json):
16 test Rust positivi, 9 documentali, audit fork. Confronto esatto di
stream, cursori, refill/cap, rejection fixture, sali, pad, root, aperture
duplicate e due catene WHIR con transcript/MAC originali. La prova AES
reale ridotta passa in 50,29 s dopo l'eccezione alle sole socketpair
locali; il precedente PermissionDenied resta separato. Nessun trial
canonicamente completo e nessuna GPU eseguita.

Il sampler misura 0,01845→0,00310 s su 262.144 campioni: 5,95× ARM.
PCS ridotta a 128 colonne: 0,01098→0,01255 s con 60 record/50.131 B;
il costo del log non è nascosto in una stima gratuita. Snapshot RNG
144 B, nessun buffer trattenuto per root; 4.096 B per sampler sequenziale.
Il census comune del positivo AES misura 116.430.690 B, zero rifiuti;
riserva runtime 256 MiB e margini rimangono condizionati alla futura
misura fisica. Il codice è compilato miratamente a un job; i test
rispettano 60 s / 2 GiB e un worker. L'assenza di `nvcc` locale lascia
la compilazione/esecuzione CUDA alla futura campagna autorizzata.

Il goal rimane attivo. Prossimo lavoro autorizzato in locale:

1. W: condividere l'owner numerico, accumuli coset, FFT finite e hash
   salato/Merkle, con parità host ridotta ed errori terminali.
2. Verificare 32 coset × blocchi da 8 colonne: 2 GiB valori e 1 GiB di
   CV BLAKE3 sono subtotal candidati. Il dominio foglia occupa 32 B;
   hashing incrementale deve preservare il mezzo blocco pendente e il
   confine fra chunk. Un Hasher generico da 1.920 B per foglia non entra:
   serve un layout compatto verificato e riuso dei valori ancora vivi.
   Se ogni coefficiente W è letto solo per il proprio blocco, il conto
   equivalente scende 1.024→128 scansioni; contributi di campo, FFT,
   sali, frontier, pad, tabelle/owner/staging e picchi restano da pagare.
3. Confrontare accumuli interi ordinari e Tensor Core a limb esatti,
   senza floating, saturazioni o nuove basi Fp3. Per A, contare le
   ricostruzioni effettive: non importare la schedule a blocchi W che
   moltiplicherebbe i replay completi. La baseline resta 512.
4. A residente→PCS senza download per riga; poi aperture/GKR/range,
   QK/PV e sincronizzazioni guidate dal profilo. Valutare TMA, fusioni e
   CUDA Graphs solo con una mappatura utile e controllabile. Preparare
   benchmark rappresentativi e conto simultaneo per il primo hardware.

Il [design attivo](../c7.1/design.md) conserva stato e prossime azioni;
questo file registra il primo checkpoint, senza anticipare l'esito dei
passi successivi o attribuire tempi ARM alla H100.
