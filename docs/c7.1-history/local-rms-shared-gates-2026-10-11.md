# Fattorizzazione RMS candidata — 11 ottobre 2026

Seguito locale della [cache folded](local-rms-fold-cache-2026-10-11.md),
con **zero certificati canonici** e pod fermo. La nuova candidata agisce
sui prodotti del core, distintamente dai callback della cache. Il runner
canonico conserva entrambe disabilitate.

## Identità e implementazione

Per ogni indice output `i` e gate `g`, sia `M(i,g)` l'insieme dei
programmi che usano quel gate a quell'indice. Il contributo originale è
`sum_p selector_p * sum_i weight_i * gate_(p,i)(V)`.
Si raggruppano i termini con la stessa maschera `M` e lo stesso gate:
`sum_(M,g) (sum_(p in M) selector_p) * (sum_(i: M(i,g)=M) weight_i) * g(V)`.
Ogni contributo originale appartiene a un solo gruppo. AND e XOR sono
commutativi, quindi gli operandi vengono ordinati. Non si sostituiscono
`x*x` con `x` o `XOR(x,x)` con zero nelle righe folded.

[SharedGates](../../rust/volta-pcs/src/c71_matrix/rms/gkr/shared_gates.rs)
costruisce il piano con Vec bounded e sorting in-place. I pesi dipendono
dalla stessa sfida del prover e vengono sommati una volta per profondità;
la geometria e le maschere restano pubbliche. Il primo round mantiene
la valutazione Booleana originale. Nei round successivi, per ogni coppia
di celle, usa il raggruppamento soltanto se il supporto pubblico predice
meno prodotti: sei per selettore vivo, sei per AND/XOR e due per Copy.
In parità sceglie il ciclo originale. La scelta non usa i valori Fp3.

L'aritmetica per gate è condivisa dalle due schedule. Riduzioni sugli
indici, endpoint byte, transcript e consumo delle correlazioni non cambiano.
Il piano vive solo nella fase di cella della profondità corrente. Il
benchmark ignorato lo seleziona con `C71_RMS_BENCH_SHARED_GATES=1`;
il default è zero, indipendente da `C71_RMS_BENCH_CACHE_BYTES`.

## Capacità, contatori e premesse

Il cap locale di 32 MiB comprende il Box, capacità dei Vec finali,
conteggi originali e sovrapposizione fra le tabelle del builder. Gli
intermedi sono rilasciati prima della cattura folded; piano finale e
cache possono coesistere, ciascuno addebitato nel picco della fase di
cella. Restano esterni allocator, stack e gli altri owner del conto
completo. Il cap del componente non aumenta arena o margini globali.

I contatori distinguono visite logiche originali e gate effettivamente
valutati. Le somme dei pesi sono addebitate una volta; le somme dei
selettori sono addebitate nelle coppie che usano il piano. Sorting,
decisioni su maschere e traffico restano costi da misurare. Meno prodotti
Fp3 non dimostra meno lavoro totale o un guadagno di tempo.

La riscrittura usa `mul_comm`, `add_assoc`, `add_comm`, `Finset.sum_mul`,
`Finset.mul_sum` e `Finset.sum_comm` nel campo. Nessun nuovo lemma Lean
raffina sorting, indici, maschere, pesi o lifetime Rust. Questi binding,
insieme al raffinamento Fp3 già aperto, restano premesse esplicite. Le
parità finite verificano fixture e non scaricano tali obblighi generali.

## Evidenze e limite

La prima build di sviluppo passa in 57,517 s, RSS aggregato campionato
2.616.860.672 B. Due test del piano passano; la wire completa ridotta
coincide col riferimento denso e conserva FS/MAC/endpoint e consumo di
tutte le 472 correlazioni. Questa prima variante raggruppava anche il
primo round: 266→192 prodotti nella fixture, dato di sviluppo distinto
dalla candidata adattiva finale.

La prima scansione pubblica completa i blocchi 1–11, 12–22 e 23–33;
34–44 termina con timeout 60 s, RSS 499.208.192 B. Il diagnostico calcolava
sia il vecchio screen sia il piano implementato, ripetendo proiezioni
identiche. La versione successiva sceglie una sola analisi e conserva
i supporti per maschera all'interno del blocco; stessi AS 2 GiB, deadline
60 s e un worker. Il timeout rimane evidenza negativa conservata.

Per il costo canonico, la somma del minimo fra i totali per round delle
due schedule è un **upper** del numero di prodotti della scelta per
coppia, non il suo conteggio esatto. Il primo round usa il totale originale.
Sono esclusi somme dei selettori, sorting, decisioni, replay, fold, byte
endpoint, statistiche del caller, PCS, AES e risposta completa.

Prima della selezione servono misura rappresentativa, conto simultaneo e
valutazione del residuo. Nessun certificato, nuovo setup AES o processo
provider è stato avviato in questo seguito locale.
