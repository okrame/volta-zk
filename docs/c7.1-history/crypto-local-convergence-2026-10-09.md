# Query W, profilo residuo e convergenza locale — 9 ottobre 2026

Il [checkpoint sorgente e verifiche](../../benchmarks/results/c71-crypto-w-query-profile-local-2026-10-09-e55e1a7b4ad0.json)
lega W residente a `ac36155`, correzione del census a `26c87d2` e Writer/profilo
a `e55e1a7`. Sono passati 14 filtri Rust e tre test Python, sotto AS 2 GiB,
60 s e un worker per invocazione. Le build mirate sono separate: 55,27 e
59,76 s, picco aggregato circa 2,58 GiB, nessuna estensione dei limiti.
Non sono compilazione/esecuzione CUDA, misure H100 o certificati D34/D35.

W iniziale usa `NativeQuery::Weights`: packed sigillato, mappa originale,
guard live prima dell'indirizzo, nessuna finestra host degli originali.
18 casi Horner includono signed, ragged, pad fino a 1536 e ordine/duplicati.
La catena WHIR D10 W conserva 2.284.920 B di wire/FS/RNG/MAC originali;
A conserva 2.285.464 B. Getter privati fanno panic nelle route residenti.
La verifica indipendente C++ e quella dell'owner coprono mapping e guard.
Il loader aggiunge un solo launch per blocco, senza nuovo scratch o fence.

La scansione completa A ritira righe numeriche, replay KV, istogrammi duplicati
e padding prima dell'hash; il test misura lo stesso arena prima/dopo scan.
L'hash usa lo stato persistente, risparmiando 194.511.872 B rispetto al replay;
non aggiunge ricostruzioni. Writer canonico prealloca 96 MiB: parità wire/FS
e confine del certificato, completion inclusa, sono verificati.

Il [census](../../scripts/c71_residual_profile.py) legge sorgente Git e ledger
pubblico legato tramite digest alla ricevuta Γ ammessa. Le query WHIR espandono
4096 righe per sottoalbero; q_eff può essere 2^20 per ciascuno di due batch.
W richiede 29.390 root block/batch: 33 launch e 64 MiB di packing D2D per
remainder, circa 1,97 TB/batch prima degli altri accessi HBM. Fattori pubblici:
19.922.807 DFT, 679.477.284 celle; range: 1.923/9.057 fence del consumer A/W,
producer esclusi. Sono conti analitici, non tempi. Almeno 581 scan complete
dell'A corrente includono commitment512, residuale35 e lineare34; callback RMS
leggono il checkpoint e non sono altre scan complete A.

Il caller canonico RMS resta `prove_sourcewise(true,None)`, senza pattern
prefix o endpoint contratto: 159 programmi, 99 livelli massimi, 347.937.024
celle vive. Il ledger ammesso fornisce 4,85×10^16 valutazioni Booleane di replay
e 9,72×10^14 moltiplicazioni Fp3 del core dopo pruning. Restano altri consumer
non-range, index/MAC/FS, PCG expansion, codec e verifica; il conto non è completo.
Il target 65 s non è risolto da una futura misura della sola PCS.

Il controllo completo ridotto Seed6 AES è prima fallito per la socketpair
vietata dal sandbox; la ripresa autorizzata solo localmente ha raggiunto 60,02 s
(exit124). Entrambi gli esiti sono conservati, senza retry a limiti maggiori.
L'oracolo Booleano ridotto, fattori, piccoli resti, range originale e wire
geometry passano. Il census iniziale aveva un errore di sintassi corretto;
il wrapper W attendeva due test Python ma ne passavano tre: i risultati sono
ri-attestati su source/binario puliti, senza rieseguirli. Le latenze canoniche
installazione/setup/inferenza/prova/verifica rimangono non misurate.

Il [conto aggiornato](../../benchmarks/results/c71-crypto-resource-inventory-local-2026-10-09-b19822b8a3fb.json)
conserva inventario e patch congelati. Il massimo nominato è A3 accumulo
5.744.879.732 B; hash A3 5.595.450.452 B e S2 publication A3, Writer incluso,
5.642.161.460 B. Sette classi hanno formule dei payload principali; quattro
restano aperte: capacità dei sei profili/metadati, proof/body/decoder,
costruzione forme prima di shrink/bind e wrapper/telemetria. Non è provato
un overflow reale, ma nemmeno un upper congiunto completo; enforcement non
significa fit. Payload 5.905.580.032 B e riserve rimangono invariati.

La revisione gestionale ha confermato progressi e sprechi: guard ridondante
4096 poi rimosso dopo il massimo pinned52883, checkpoint helper/owner/caller
troppo frammentati e 19 commit sui documenti attivi in circa 30 ore.
Il lavoro prosegue con verifiche disgiunte delle lacune precise; build/test
rimangono seriali e i cinque documenti vengono riconciliati insieme.
Γ attuale è l'unico ammesso, senza ottimalità prestazionale dimostrata.
Cercare scale diverse sarebbe una nuova relazione numerica/ammissione;
il goal corrente conserva Γ e gli stessi circuiti/protocollo.

Goal ancora attivo. Restano conto completo, trattamento del lavoro RMS e
profilo delle altre famiglie; nessuna nuova H100 o durata è autorizzata.
