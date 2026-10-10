# H100: prefisso KV inizializzato — 10 ottobre 2026

Il [diagnostico A](h100-a-diagnostic-2026-10-10.md) termina al confine dei
tile originali. Il [record locale](../../benchmarks/results/c71-prefix-local-2026-10-10-3ea1e4a82d07.json)
riproduce lo stesso errore con quattro word scritte in una capacità da
12, senza pesi o buffer canonici. Il test fallisce prima della correzione
in 10,030 s, e passa sullo stesso binario dopo la modifica del confine C++.
La fixture compila il runtime C++ corrente a ogni invocazione; i due hash
sono conservati. La build mirata Rust impiega 56,796 s con RSS aggregato
2.585.444.352 B, sotto 120 s/3 GiB. Il record dichiara `git_dirty:true`.

PCS iniziale, closure lineare e residual ora validano lo span su
`initialized`, anziché richiedere che eguagli l'intera capacità. Rifiutano
anche un contatore incoerente oltre capacità. Il kernel residual riceve
lo stesso limite scritto. Il gather di byte già usava questa convenzione.
Capacità, scheduling, buffer, valori, copertura unica e MAC originali
restano invariati; non si legge o inizializza artificialmente la coda KV.

Passano sei test locali, con un worker, AS 2 GiB e 60 s per invocazione.
Il nuovo test include 12 casi nei tre consumer: prefisso esatto ammesso,
span che sfora di una word, coda interamente non scritta e overflow di
indice rifiutati. Le fixture di parità ora riservano tre volte il prefisso:
passano albero A/radici/aperture/istogramma, endpoint lineari, full wire,
FS e MAC originali, residual/coefficienti/retention. Restano verdi i
28 rifiuti precedenti dell'owner A.

Serve ancora la nuova libreria sm_90, i 15 test reali con le fixture
aggiornate e un nuovo componente A. Il binario canonico Rust `3ea1e4a`
è riusabile: queste modifiche Rust sono soltanto nei moduli di test;
il cambiamento di produzione è nella libreria C++. Correlazioni e
monete del trial terminale non vengono importate.

Non esiste un lemma Lean che raffini il contatore `initialized` del
driver. L'invariante del prefisso contiguo scritto rimane una premessa
implementativa esplicita, sostenuta da controlli e parità finita.
Nessun nuovo credito di protocollo o picco completo deriva da questi test.
