# RMS misto: identità dei momenti e supporto pubblico — 11 ottobre 2026

Il [confronto H100 byte](h100-rms-byte-paired-2026-10-11.md) riduce
l'endpoint ma lascia invariato il core della cella. Il seguito locale
prepara una fattorizzazione degli stessi primi cubici, senza selezione
canonica o hardware acceso. Zero certificati canonici.

## Identità e controllo

L'[oracolo](../../scripts/c71_rms_prefix_moments.py) riprende i momenti
EXP30, generalizzandoli ai programmi RMS misti. Per ogni suffisso k e
programma p conserva la maschera delle posizioni di prefisso assegnate
pubblicamente a p. Gram e termini lineari sommano Eq originale del
suffisso, pesi dei gate originali e prodotti di bit delle righe originali.
Dopo i pesi, programmi con maschera uguale sommano le stesse matrici.
La valutazione usa la Eq originale del prefisso nella stessa componente
selector e gli stessi fold MSB. Non costruisce un nuovo predicato o MAC.

**La maschera limita soltanto il selector.** Le wire folded devono
conservare anche le righe appartenenti ad altri programmi: filtrare
quelle righe cambierebbe il polinomio GKR originale. Il padding conserva
wire zero; zero/uno o cancellazioni delle sfide non eliminano supporti
strutturali. Il builder non riceve le nuove sfide del round corrente.

Tre [controlli Python](../../tests/test_c71_rms_prefix_moments.py) passano
entro AS2 GiB/60 s/un worker: valori del cubico contro un fold denso
indipendente con programmi/gate diversi, proiezione contro ogni cella
originale e rifiuti di geometria/padding/parent. Il confronto aritmetico
usa l'oracolo indipendente F97[u]/(u³−2), con punti nonbase e zero/uno,
per i primi2/3/4 round. Non è un test Goldilocks/Rust, una wire completa
FS/MAC o un nuovo lemma Lean. Il conto di supporto fino a8 bit non è
una validazione aritmetica o native di quei prefissi maggiori.

## Proiezione senza enumerare il dominio

Input originale congelato:536.870.912 celle padded,347.937.024 vive,
159 programmi e3.117 intervalli disgiunti. Gli eventi ai confini delle
proiezioni MSB producono maschere pubbliche, senza valori privati,
Eq(N) densa, replay o generazione di sfide.

| Bit prefisso | Coppie programma/maschera | Maschere distinte | Payload dopo pesi e fusione B |
|---|---:|---:|---:|
| 2 | 418 | 7 | 3.360 |
| 3 | 632 | 18 | 31.104 |
| 4 | 889 | 64 | 417.792 |
| 5 | 1.157 | 165 | 4.181.760 |
| 6 | 1.606 | 422 | 42.132.480 |
| 7 | 1.908 | 827 | 327.730.176 |
| 8 | 2.242 | 1.359 | 2.145.871.872 |

È solo payload dei momenti per maschera: esclusi metadati, builder,
raw counts, asse gate prima dei pesi, replay/fold, sovrapposizioni,
owner, CompactFrames, proof/PCG/PCS e picco fisico. `credit:false`,
`complete_capacity:false`, `complete_work:false`. Il payload prima
della fusione delle maschere a4 bit sarebbe5.803.392 B.

## Impedimento del builder e prossimo passo

La schedule BMMA EXP30 a contatori interi non si trasferisce conservando
l'intero asse dei gate RMS. La profondità42 contiene335.044 gate binari
originali: con16×16 coppie di posizioni,192 bit-plane Eq e contatori
u32, **65.872.330.752 B** per i soli contatori, già oltre il cap.
È una condizione di quel layout non compresso, non un limite universale
alla relazione o a un builder diverso. Sono esclusi maschere aggiuntive,
Copy/XOR lineari, staging, padding dei frammenti e tutto il resto.

Servono blocchi limitati di gate/maschere e riduzione parziale prima
che i contatori si accumulino. L'oracolo corrente applica pesi del gate
su ciascuna sorgente: non gli si attribuisce il risparmio di una pesatura
tardiva ancora da implementare. Il prossimo passo è il conto completo
per quei blocchi, inclusi riuso o replay dello staging, prodotti dei pesi,
traffico host/device e lifetime nel ledger simultaneo; poi caller nativo
con replay/fold/core e parità Goldilocks/wire. Nessun kernel del solo
core, selezione del runner o trial completo dai soli payload.

Distributività del campo, corrispondenza fra maschere e assegnamenti,
ordine MSB e builder bounded restano premesse implementative da
scaricare; nessun nuovo lemma Lean o raffinamento runtime.
