# RMS — batching dei gate del prefisso preparato

Segue il [trial159/99 verificato](h100-rms-mixed-all-parity-2026-10-11.md),
il cui prefisso lancia tre kernel per ogni chunk di ogni programma
presente nella finestra. Il [conto verificato](h100-rms-native-schedule-parity-2026-10-11.md)
rimane riferito alla SHA `92afea54`, non alla nuova candidata.

La candidata appiattisce gli stessi gate dei soli programmi pubblicamente
presenti in chunk512 comuni. Un descrittore pubblico16 B per programma
lega indice appiattito, range originale e maschera selector originale.
Binary/linear moments conservano i gate originali tramite lookup del
descrittore; late weight scrive ogni maschera separatamente, nell'ordine
originale dei gate. Le maschere nonempty dei programmi della stessa
finestra sono disgiunte, quindi le destinazioni sono distinte; il runtime
rifiuta anche ID duplicati. Nessun atomic, nuova colonna o endpoint.

Staging host massimo16×P B aggiunto alla shadow già posseduta del prefisso;
16×P B device aggiunti al buffer Eq privato, oltre all'align allocator.
La shadow dei descrittori rimane immutabile fino al fence positivo;
errori/fence incerti trattengono ownership e charge fino a close/exit.
Prima della finestra successiva il fence originale è obbligatorio.
L'ABI pubblica, source token/checkpoint, tail e indici restano gli stessi.

L'owner aggiunge il rifiuto dell'H2D del nuovo piano dopo entrambi gli
upload dei frame:23 errori del prefisso da eseguire. Owner/Rust,
coefficienti densi, caller originale e159/99/wire devono
essere rieseguiti sul pod; nessun risultato della candidata attribuito
prima dell'esecuzione. Le prove originali restano il riferimento, senza
shortcut per token/PCS o nuove correlazioni. Associatività, mapping dei
gate/maschere e capacità/lifetime CUDA restano premesse di raffinamento
aperte; nessun nuovo lemma Lean o ammissione canonica.

CPU AS64 GiB, CUDA senza AS ma con stop fisico/arena/deadline. VM solo
editing/controllo. Pod originale e guard attivi; calcolo23:43:00 UTC e
hard stop12 ottobre00:13:00. Zero certificati, byte/statistica GPU,
conto completo e lavoro canonico ancora aperti.
