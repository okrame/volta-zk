# Gather originale per il range — 2026-10-03

Questo checkpoint implementa il reader del piano range, non il prover
canopy/Gram. Autorità corrente: [design](../c7.1/design.md),
[specifiche](../c7.1/specs.md) e [sicurezza](../c7.1/security.md).

## Collegamento locale

Il piano scelto richiede finestre di byte originali nell'ordine
`[tail][prefisso già folded][u della nuova finestra Gram][sottoalbero]`,
con fold MSB. Il [piano storico](preflight.md) resta la provenienza delle
26 passate analitiche; aggiungere una cache contigua al getter scalare
non realizza quell'ordine e non giustifica quel numero di ricostruzioni.

[`RangeWindow`](../../rust/volta-pcs/src/c71_matrix/gemma/bytes.rs) valida
dominio, allineamento dyadic, cap di 2 GiB e conservazione del sottoalbero.
Una finestra fissa un sottoinsieme dei bit dell'indirizzo originale.
Due intervalli dyadic si intersecano se i rispettivi bit fissi comuni
sono compatibili: il selettore visita le tessere, non tutti i byte A.
`offset` restituisce la destinazione nel buffer riordinato, senza cambiare
encoding, layout digest o commitment.

[`Prepared::range_window`](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_ordered.rs)
riusa lo scanner causale e i controlli di copertura per le sole sorgenti
selezionate. Ogni sorgente selezionata è emessa una volta per chiamata;
dipendenze condivise usano la chiusura già implementata dallo scanner.
Gli owner di checkpoint, istogrammi e KV restano gli originali. Il suffisso
flat è inizializzato a zero; gli zeri interni signed sono emessi biased.
La validazione avviene prima di toccare il buffer; un errore numerico o di
copertura invalida l'output parziale e viene propagato.

## Controlli e limiti

Il [record locale](../../benchmarks/results/c71-range-gather-local-2026-10-03-0e61ef0826a5.json)
registra 15 test Rust e 11 Python, build e lint correctness/suspicious
sulla revisione pulita `0e61ef0826a5`. Nessun test/build fallito in questo
checkpoint; rimangono warning non bloccanti. Conserva anche la verifica
precedente e l'aggiunta test-only dei descrittori della passata iniziale.

Il confronto bit-per-bit enumera D1–D7, tutte le geometrie ammesse,
ogni indirizzo e ogni intervallo dyadic. Controlla copertura unica,
ordine e selezione delle tessere contro un oracle per enumerazione.
Il controllo D34 costruisce soltanto descrittori delle geometrie delle
26 passate: non alloca né legge il dominio canonico.
La fixture i48/i32/i16 confronta il gather e le sorgenti selezionate con
il mapping packed indipendente, inclusi il suffisso esterno e gli estremi
signed. La fixture numerica canonica usa un solo operatore sintetico:
confronta finestre ricostruite, checkpoint e istogrammi e verifica i rifiuti
prima di modificare l'output. Non legge pesi reali.

Il reader non è ancora invocato dal prover range, che continua a usare
la rigenerazione scalare. Manca il collegamento canopy/Gram/retention,
la gestione fallibile dei callback aritmetici e la verifica del transcript
e dei MAC originali di quel consumer. Nessuna passata canonica, nuova prova
range ottimizzata, misura fisica, esecuzione CUDA o garanzia Seed6 è acquisita.
Il limite per-buffer non conta la memoria simultanea degli altri owner.
Restano zero certificati canonici e il superamento analitico dei 40 MB
nelle continuazioni; non cambiano autorizzazioni o hard stop provider.
