# C7.1 — gate condivisi con supporto RMS originale, 11 ottobre 2026

Il precedente rapporto 0,221077 considerava tutti i programmi attivi in
ogni coppia. Lo screen nuovo usa i 3.117 intervalli dyadici delle 421 norm
originali, 159 ricette, 347.937.024 celle vive su 2^29, e tutte le 99
profondità. Ricostruisce esattamente il conto corrente di
844.006.203.160.300 prodotti Fp3, dopo pruning pubblico e primo round
Boolean. L’unione dei residui per ogni classe di selettori determina quali
coppie possono contribuire, senza dati privati o cancellazioni numeriche.

La fusione statica dei gate per classe di selettori darebbe
559.922.206.698.409 prodotti (rapporto 0,663410). Conservando il percorso
corrente nei primi due round, dove quella fusione peggiora il conto, il
residuo sarebbe 542.419.458.937.257. Sono costi del solo core; costruzione
del piano, somme dei selettori, replay, fold delle righe e callback restano
esclusi. Non è un algoritmo implementato né una previsione di tempo.
Questa riduzione da sola non risolve l’impedimento RMS della campagna.

L’unione modulo è confrontata esaustivamente con le celle per domini
2/4/8. Tre screen locali separati coprono profondità 1–33, 34–66, 67–99:
47,48/49,58/32,28 s, AS 2 GiB, un worker e timeout 60 s per screen.
La build finale passa in 58,448 s con RSS aggregato 2.594.050.048 B entro
3 GiB/120 s. Un primo build fallisce per tipo intero ambiguo nel test;
la correzione aggiunge `usize`, senza cambiare runtime o protocollo.
Questi primi log hanno working tree modificato e restano preflight;
il record pulito successivo deve conservare gli stessi input pubblici.
