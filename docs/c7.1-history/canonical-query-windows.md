# Prime query A a finestre — 3 ottobre 2026

Checkpoint locale successivo allo
[scanner del commitment iniziale](canonical-initial-scan.md).
Le istruzioni correnti rimangono nei [cinque documenti attivi](../c7.1/design.md).
Il [record sulla revisione pulita fa8a161](../../benchmarks/results/c71-query-windows-local-2026-10-03-fa8a1617a674.json)
conserva 24 test Rust, 9 controlli documentali, due rifiuti CLI, build e
lint passati. Conserva anche il fallimento di sviluppo: il nuovo fixture
D10 assumeva 32 coset anziché i 64 della configurazione effettiva; ora
il conteggio atteso è derivato dai parametri PCS. `credit:false` e
`readiness:false` rimangono espliciti.

Le query precedenti chiamavano il getter scalare durante ogni blocco di
resto polinomiale. Per A ciò riattivava finestre da 128 byte, incompatibili
con la ricostruzione numerica pianificata. Il raccordo ora usa direttamente
il metodo `Prepared::window`, condividendo il buffer fra le due colonne
originali coperte dalla finestra D34 da 256 MiB. Ogni colonna conserva
l'ordine high-to-low dei blocchi. Nelle geometrie ridotte la finestra
copre ugualmente due colonne, senza allocare 256 MiB per un test piccolo.

Il reader riceve solo indice pubblico e slice di byte originali; non
riceve pad PCS o correlazioni. Non legge il suffisso esterno zero.
Gli errori interrompono immediatamente il batch. Lo storage appartiene
alla singola chiamata delle query, non al root storico: tre A non
trattengono tre reader da 256 MiB. Il `Vec` non è trattenuto dal tree dopo
il ritorno; ciò non dimostra rilascio di RSS, fence o liberazione GPU. Le finestre
canoniche riusano i controlli di copertura dello scanner per sorgente.

Il precedente percorso costruiva una matrice completa `Coefficient`
e una seconda matrice di limb base. La conversione ora scrive direttamente
nel risultato finale. Il payload duplicato rimosso al cap iniziale è
`2^21 * 128 * 8 = 2.147.483.648 B`, un conto statico, non un picco misurato.
Restano l'output richiesto, i descrittori di riga, i fattori/intermedi dei
resti, entrambi i twiddle, cache/sali/sottoalberi Merkle e gli owner della
ricostruzione numerica. Il totale fisico simultaneo resta aperto.

I controlli coprono prefissi vivi vuoti, parziali e completi, più finestre
condivise fra colonne, blocchi piccoli o più lunghi della colonna,
duplicati, pad originali nonzero e rifiuti di shape/errori del reader.
Le righe sono confrontate con Horner indipendente. Un reader alterato
fallisce l'apertura del root trattenuto. La catena PCS D10 a monete fissate
usa il nuovo reader e S1 trattenuto: confronta byte, transcript, monete,
endpoint e verifica coi MAC originali; la key errata deve fallire.
Questi sono controlli ridotti, non certificati canonici.

Restano locali range a finestre, stato sourcewise oltre D16, stadi PCS
extension grandi, workspace densi, integrazione CUDA esatta, partizione
completa dei tempi, memoria simultanea e composizione canonica positiva.
Non sono dipendenze risolvibili acquistando hardware. Pesi/calibrazione e
misure H100 richiedono autorizzazione; rimane l'hard stop provider su
deadline/controllo di spesa. Nessun certificato canonico acquisito, uso
GPU o spesa; superamento analitico dei 40 MB nelle continuazioni e
obblighi Seed6 invariati.
