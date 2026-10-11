# RMS — candidata GPU per gli indici originali

Segue il [fold/core verificato](h100-rms-cell-tail-parity-2026-10-11.md) nella
stessa campagna autorizzata, senza estensione: calcolo fino23:43:00 UTC,
guard00:03:00, hard stop12 ottobre00:13:00. In questo snapshot indici e
ottimizzazione del binding/live sono preparati, non ancora validati.

Il caller esplicito ricompila gli stessi gate And/Xor/Copy e pesi pubblici
originali, dopo il ritiro del piano della cella. Un token privato del runtime
carica gate/range, precedente e selector canonici; moltiplica i pesi per
selector sulla GPU. Conserva precedente e working vector separati; ogni
challenge già emessa aggiorna lo stesso Eq degli edge e il fold MSB.
Due riduzioni quadratiche originali, coefficienti terminali e scalar X/Y
ritornano al medesimo prover per round/FS/MAC e tag. Nessuna correlazione
nuova o endpoint alternativo. Coefficienti ridotti per blocchi256 e tre
coefficienti, senza tabella W².

Tre buffer privati: gate40 B ciascuno più8 B/range e24 B/selector;
2*width*24 B per precedente/working, `(6+3*ceil(gates/256))*24` B scratch.
Staging posseduto host copia tutti gli input prima delle H2D, resta
addebitato fino al fence riuscito; challenge shadow768 B e pubblicazioni
144 B. Stato riusa la transaction disgiunta, owner permanente42.496 B
invariato. Il terminale si pubblica solo dopo i tre rilasci riusciti; errori
poison/cleanup incerto non rimborsano debito o ritentano free incerto.
Due nuovi simboli obbligatori, nessun fallback.

Gli intervalli originali compilati eliminano scansioni complete della
geometria e il binary lookup per ogni byte del binding. La stream rimane
identica, con un byte/u16 per ogni cella e chunk4096 B. Massa Eq dei vivi
usa differenze delle somme sui prefissi originali, anche per challenge
zero/uno, senza divisione. Contatori bit-zero/count derivati dai range
pubblici; contatori live distinguono il lavoro delle somme sui prefissi.
Il default RMS conserva il percorso precedente.

Test preparati:30 rifiuti owner e due geometrie, length/history/foreign
owner Rust, simboli obbligatori; binding/live contro denso per3/256/421
programmi e domini1..512; indice GPU contro coefficienti sparsi originali
su width1/2/8/128/512 e774 gate, due serie di challenge,80 coefficienti e
10 terminali. Caller originale ridotto da verificare sul nuovo checkout.
I driver stub non danno credito matematico; parità reali richiedono H100.

Somme di intervalli, Eq edge/fold/polinomi originali e implementazione
della riduzione restano premesse di raffinamento non scaricate da nuovi
lemmi Lean. Byte/statistica GPU,159 programmi/99 profondità e conto
simultaneo completo restano aperti. Nessuna selezione canonica o credito
al target65 s; zero certificati.
