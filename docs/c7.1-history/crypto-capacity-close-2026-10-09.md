# C7.1 — capacità tipate e chiusura locale, 9 ottobre 2026

Checkpoint storico; istruzioni correnti nel [design](../c7.1/design.md).

Il [record immutabile](../../benchmarks/results/c71-crypto-capacity-local-2026-10-09-d4215fafd878.json) lega sorgente pulita `d4215fafd878`,
log positivi/negativi, patch congelate e formule dei tre reviewer.
Il percorso resta misto; nessuna compilazione CUDA, H100 o campagna nuova.

La produzione trasferisce le forme W originali evitando il clone, riserva
esattamente il record bind, legge `/proc` con cap 64 KiB, compatta le forme
KV storiche e prevalida entrambe le batch complete prima delle chiusure
W/history. Check condiviso con bind, nessun record FS o correlazione
consumato. Gli upper preconstructor restano senza clamp. Il verifier
costruisce le proprie batch dopo il certificato completo, quando le batch
P sono già rilasciate; il ledger iniziale che le sommava è conservato come
modello provvisorio corretto, non come fallimento del protocollo.

Build seriale O0/128 unità: 56,98 s, RSS aggregato 2.560.106.496 B.
Preflight/cap/compattazione, record byte/FS, forme, metadati, wire/decoder,
Batch.take, progress/metrics passano. La prova lineare nativa completa D10
passa in 43,71 s, confrontando byte, transcript e MAC originali.
Conservati: errore compilazione MulAssign Fp3, timeout build256,
identity bind erroneamente8 B (actual u32=4 B), arena fixture 262 KiB
insufficiente per la route W selezionata e timeout KV 60 s. Solo la fixture
lineare è portata a 2 MiB; limiti produzione/test invariati.

Il ledger enumera 653 fasi/11 classi, zero subtotal oltre il cap.
Massimo: S2 A3 query publication 5.878.675.986 B, residuo 26.904.046 B;
A3 accumulo 5.834.526.966 B. Profili Γ reali, sei profili: 49.103.484 B.
Setup AES/MR19/guard/cGGM: 2.263.972 B aux oltre seed/Audit/context.
RMS compilatore/pruning 723.826.724 B, preparato 457.659.280 B;
compiler e CompactFrames hanno lifetimes distinti. Formule da sorgente,
non misure di esecuzione completa; runtime fisico non verificato.
Resta condizione manifest path/argv ≤4.096 B e `joint_admitted:false`.

La revisione gestionale conferma codice avanzato ma anche dispersione:
checkpoint piccoli ripetuti, review sovrapposte, bounds conservativi non
ancorati al caller. Questo blocco usa incarichi finiti, integrazione root,
una build alla volta e un solo aggiornamento finale dei cinque documenti.
Il prossimo lavoro sostanziale è una valutazione RMS/GKR meno costosa sugli
stessi circuiti, con parità e profilo rappresentativo, poi verifica integrata
e procedure H100. PCS sola non chiude il target 65 s; Γ ammesso resta riusabile,
non un optimum prestazionale dimostrato. Goal ancora attivo prima del trial.
