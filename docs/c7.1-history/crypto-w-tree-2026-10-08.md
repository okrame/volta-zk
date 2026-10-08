# C7.1 — Tree W residente, 8 ottobre 2026

Preparazione locale del goal H100, successiva ai
[componenti accumuli/FFT](crypto-w-scan-fft-2026-10-08.md).
Nessun hardware o tempo pagato aggiuntivo è autorizzato. Γ conserva le
identità ammesse del workload pinned; numerica, producer, scale e tabelle
non cambiano. Il goal completo resta aperto, soprattutto A→PCS e resto
del percorso crittografico.

## Decisione e collegamento

`experiment-cuda` seleziona il commitment iniziale W sul runtime comune
già proprietario dell'unica W packed. `reference-cpu` conserva la schedule
precedente. Solo W usa 32 coset per scan e ring da otto colonne; A conserva
quattro coset e 512 ricostruzioni iniziali, senza aumento implicito.

Il builder mantiene pad, prescan del sampler privato, seek/replay dei sali,
root naturale e cache originale con `cut=4096`. Riempie quattro colonne
alla volta con accumuli signed esatti e FFT in-place, poi hash incrementale;
rilascia potenze e ring prima delle rispettive fasi Merkle. Il frontier
unisce gruppi consecutivi. Legge soltanto digest superiori e flag.
Identità/Arc/layout, shape, copertura e guasti del driver sono terminali
per l'owner; non selezionano il riferimento CPU. Il getter originale
rimane quello delle aperture. I producer numerici non ricevono monete PCS.

Per la geometria pinned: 128 scan equivalenti, 7.858.520.391.680 B di
letture W logiche, 125.736.326.266.880 prodotti signed, 549.755.813.888
celle FFT, 4.294.967.296 foglie e 4.294.967.295 nodi. Questi sono conti
analitici, non traffico HBM misurato o tempi H100. Le monete e i sali
restano CPU; prescan e replay effettuano due passaggi del sampler originale.
Confronto Tensor Core, A residente e accelerazione delle aperture sono aperti.

## Parità e limiti delle verifiche

La fixture D15 usa W ragged signed con estremi ±32767, suffisso zero,
pad originali e due gruppi di 32 coset. Root, pad, conteggio di lavoro e
aperture su confini, duplicati e indici fuori ordine coincidono con il
riferimento. Nessuna chiamata al getter scalare durante la costruzione
residente. Otto guasti rifiutati, cleanup completo e nessun fallback.

La verifica composta confronta l'intera prova serializzata, codec,
transcript, posizioni RNG, target e chiusura sui MAC originali. Solo in
questa fixture le righe iniziali provengono dalla tabella eager del
riferimento (16 MiB, conteggiati nel budget): evita di ripetere il vecchio
evaluator CPU per ogni foglia iniziale. Tree, sali, rigenerazione/pruned
paths e tutti gli stadi sourcewise successivi sono quelli effettivi.
Non introduce una cache in produzione e non misura il replay originale
delle aperture. La parità del getter effettivo è il test Tree separato.
I MAC della fixture sono ideal; il backend canonico conserva PCG reale AES.

Il test combinato D15 senza tabella supera ancora 60 s, con memoria molto
inferiore a 2 GiB. I prefissi durevoli mostrano batch query da circa 4,1 s
prima delle ottimizzazioni e circa 2,9 s dopo; le prove complete fallite
restano failure. Il test pesante è conservato ignored come obbligo aperto,
senza estendere il limite né assegnargli un pass. Piccoli divisori monici
di grado ≤8 usano divisione diretta; il pad non viene separato quando il
messaggio entra nel batch. Test indipendenti verificano tutte le basi Fp3,
duplicati, pad/suffissi e conteggio delle letture originali. Il microbench
confronta i due metodi nello stesso binario; non trasferisce il rapporto
a tempi H100 o a tutta la PCS.

Driver host simulato e aritmetica condivisa: nessuna esecuzione CUDA,
compilazione sm_90 o parità hardware. Rimangono le assunzioni di
raffinamento di mapping, arithmetic e scheduling dichiarate nel design;
nessun nuovo lemma Lean di implementazione è acquisito.

## Risorse e correzione del conto

Due flag da 256 B convivono durante riempimento/hash. Il subtotal device
corretto è **3.736.793.344 B**, +256 B rispetto al record del componente
precedente, che resta immutabile. Comprende ring, CV, potenze basse/alte,
twiddle, pad, frontier, banda di sali, tile e i due flag.

Payload host nominati 89.292.232 B; con upper device replay 785.789.696 B
l'envelope conservativo è 4.611.875.272 B. Restano 1.293.704.760 B sul
tetto payload per gli altri owner host, conteggiati dall'allocatore comune.
È un'unione conservativa dei componenti, non un picco canonico misurato.
Il budget continua a contare tutte le capacità Rust/C++/CUDA e fallisce
prima della prenotazione; riserva fisica e margine restano da misurare.
`initial_native_peak_capacity_bytes` è l'high-water dell'owner comune,
comprende anche suoi buffer esterni al builder e non va risommato al ledger.

Le build locali usano un job, dipendenze O2 e crate principale O0; RSS
compiler è distinto dai test 60 s / 2 GiB. I tentativi O1 con AS 3 GiB
falliscono per allocazione, quello con AS 4 GiB raggiunge 60 s. Quest'ultimo
`wait4` non copre il compiler non raccolto da Cargo sul timeout: il suo
RSS basso non è un limite osservato del compiler. I log e i fallimenti
sono conservati con la nuova evidenza del checkpoint pulito.

## Nuova campagna

Prima viene completata la preparazione locale dell'intero goal. La nuova
campagna richiede autorizzazione esplicita di hardware e durata. Compilare
la libreria completa ABI 4 per sm_90, rieseguire parità e arresti sul device,
quindi misurare installazione/setup/inferenza/prova/verifica separati,
trasferimenti, sampler/FFT/hash, conteggio A e massimo fisico congiunto.
Non assumere accelerazione otto volte dal solo numero di scan W.
