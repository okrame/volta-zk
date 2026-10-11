# C7.1 — pool e nuovo stop fisico, 11 ottobre 2026

Il [record A async04](../../benchmarks/results/c71-certificates-a-async04-2026-10-11-a525ecf8.json)
conserva SHA pulita `a525ecf8`, tre parità H100 positive e il componente
O=0 fermato a **82/512 gruppi**, dopo 1.288,675 s complessivi. Il lungo
caricamento W precede la fase A; l’ultimo checkpoint A è a 543,039 s.
Il monitor ferma il processo a 6.416.604.672 B contro 6.174.015.488 B.
Payload osservato massimo 5.688.602.642 B. GPU idle dopo teardown.
Zero root A complete, zero certificati; Γ originale invariato.

La traccia corretta conserva 814 record in 458.216 B: il file non si
esaurisce. Pool slack massimo 86.097.152 B, stack CUDA sempre 256 B.
Nell’ultimo step campionato la memoria GPU cresce di 522.190.848 B e
l’RSS host resta invariato. L’ultimo evento dell’owner è prima di un
fence di `c71_range_release`: backing pool 5.268.045.824 B, con
898.522.624 B CUDA oltre W e backing pool. Questo localizza una crescita
esterna al backing registrato; non identifica un kernel, un’allocazione
interna del driver o un altro processo. Il pool non risolve lo stop.
La variante con riserva limitata alla fase A resta non selezionata.

Il launcher A conservato impostava AS CPU 128 GiB, in contrasto con i
64 GiB autorizzati; build e parità usavano 64 GiB. Nessun limite fisico
è aumentato, ma la deviazione operativa resta un fallimento. Il monitor
ora limita autonomamente il proprio AS a 64 GiB, senza aumentare un
limite più stretto e senza cambiare l’hard limit necessario al figlio CUDA.
I nuovi launcher devono usare 64 GiB; soltanto il figlio CUDA lo rimuove.

Nuova ipotesi da implementare e verificare: durante la ricostruzione A
le colonne oltre il prefisso originale sono zero pubblico; il padding
privato viene applicato dopo il ritorno del producer. Rinviare il backing
fisico di quelle colonne può ridurre la sovrapposizione con il replay,
conservando 128 colonne, quattro coset per gruppo e tutti i 512 gruppi.
Nessuna riduzione è ancora selezionata o accreditata; servono controlli
di mapping, lifecycle, contabilità e parità prima di un nuovo trial.
RMS/GKR completo rimane un impedimento separato.
