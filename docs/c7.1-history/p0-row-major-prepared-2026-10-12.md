# P0 — lettura per righe preparata, verifica pendente

Nel corpo canonico, `Auxiliary::compact` raccoglie X con loop column→row.
Il reader `Prepared::value` conserva una sola `(source,row)` e ricostruisce/
stagia quella riga al miss; per una matrice con più righe il loop cambia
riga a ogni valore. È un costo dedotto dal codice, non un profilo hardware
che attribuisca tutto il tempo del body. Il processo reale59788 è vivo,
prover thread68099 running al controllo12:07 UTC; gli altri attendono.

La candidata usa row→column per X e W, con un getter per parola come prima.
Ogni colonna accumula gli stessi termini in ascending row order: stesso
Fp3, output, padding, point/FS/MAC/correlazioni e capacità dei due Vec.
Lookup/output e ramo Norm W invariati. Non si passano query/monete al
producer: i getter restano originali deterministici della sorgente sealed.
Nessun nuovo lemma o premessa crittografica; locality/lifetime e reader
immutabile restano le premesse implementative esplicite del design.

La fixture originale ragged3×5/inner3 conserva l’oracolo indipendente di
valori e rifiuti; nuovi contatori impongono6 caricamenti riga A (3 output,
3 input) e5 transizioni W. Compilazione, parità della fixture, caller/wire
originale e produzione sono pendenti: non dichiarare speedup misurato o
selezione verificata. Test/build restano sul pod autorizzato; nessun run
locale pesante o nuovo hardware/durata. Il run canonico16d60d38 resta vivo
con il codice originale e la sua stessa sessione; non hotpatch, non import
KV/journal/correlazioni e non attribuire questa candidata al run attuale.

Zero certificati. Fine calcolo13:19:04, stop massimo13:49:04 UTC nella
finestra originale di sei ore. Segue verifica della candidata quando
compatibile con l’evidenza del run in corso e la durata autorizzata.
