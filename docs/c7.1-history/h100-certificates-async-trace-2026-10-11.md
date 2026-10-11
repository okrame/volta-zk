# C7.1 — traccia del pool a 39 gruppi, 11 ottobre 2026

Il [record](../../benchmarks/results/c71-certificates-a-async03-2026-10-11-ab181fdb.json)
conserva il source pulito `ab181fdb`, tre parità H100 passate e il nuovo
componente O=0. Termina negativo a 528,897 s, **39/512 gruppi**, quando
la traccia raggiunge 16.777.021 B su 16 MiB: 29.652 record. L’errore del
logger è terminale e il monitor conserva anche la transizione W irrisolta.

Nessuno stop fisico è osservato: il massimo campionato è 6.062.788.096 B,
sotto 6.174.015.488 B; payload osservato 5.688.616.627 B. Lo slack massimo
registrato del pool è 86.097.152 B, sotto i 128 MiB preaddebitati. Sono
un prefisso e campioni, non il picco completo o un’ammissione. GPU idle
dopo teardown, zero root A complete e zero certificati.

La revisione del filtro sottrae W e la riserva fisica effettiva del pool
quando decide se registrare una variazione di almeno 16 MiB. Il filtro
precedente sottraeva i soli buffer logici e registrava anche normali
variazioni della cache già addebitata. I controlli used/reserved e cap
rimangono eseguiti a ogni confine, anche quando il record viene omesso;
ogni snapshot di gruppo resta registrato. Il monitor indipendente non
cambia e conta tutta la memoria. Il test simulato verifica che 32 MiB
di backing noto non generino un falso spike, mentre una crescita esterna
di 20 MiB venga conservata. Cap file 16 MiB, stack, owner e riserva
payload rimangono invariati. Prossimo trial: nuovo O=0, stessi 512 gruppi,
con deadline diagnostica finita entro la campagna. RMS e lifetime della
riserva nel ledger generale restano aperti.
