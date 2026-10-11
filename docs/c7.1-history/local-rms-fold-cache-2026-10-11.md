# Cache folded RMS candidata — 11 ottobre 2026

La campagna hardware è chiusa; **zero certificati canonici**. Questa
modifica locale affronta le riletture RMS, senza risolvere il costo del
core GKR. Il prover canonico continua a usare budget zero. Γ, relazione
intera, geometria PCS, NoPeek, correlazioni ed endpoint restano invariati.

## Algoritmo e conto

[CellCache](../../rust/volta-pcs/src/c71_matrix/rms/gkr/cell_cache.rs)
trattiene righe Fp3, selettori e supporti soltanto quando la loro capacità
entra in 16 MiB. La prima cattura usa la scansione originale; dopo ogni
sfida il medesimo fold `a + r*(b-a)` riduce le due metà. Il ciclo dei gate
è invariato. Il supporto viene unito con OR, senza usare il valore del
selettore come criterio: sfide zero/uno o cancellazioni non eliminano un
programma strutturalmente presente. Un errore del getter lascia la cache
incompleta e ne impedisce il consumo. Geometria e budget sono ricontrollati.

Per `n` celle attive, width `w` e `P` programmi, il payload è
`n*((w+P)*24+P)` B, oltre al Box contenente metadati e tre Vec. Si
addebitano le capacità effettive, non le lunghezze troncate. La cache è
distrutta alla fine della fase di cella della singola profondità, prima
delle riduzioni degli indici. Il picco locale include anche lo scratch
preesistente e il replay packed; il limite della cache non è un nuovo
cap globale o un'ammissione del picco fisico. Il controllo Option/Box sullo
stack e l'overhead allocatore restano nel conto completo da verificare
prima della selezione.

Sulle 99 shape pubbliche originali e 159 ricette, la cattura avviene ai
round 17–22 (indice da zero). Con un bound metadata conservativo di 256 B,
la capacità massima è 16.675.072 B; le soglie sono identiche per ogni
metadata da 0 a 256 B. I callback originali delle celle diventano
718.142.017.536 rispetto a 998.927.195.904: 280.785.178.368 in meno,
−28,1087%. I callback dei selettori diventano 1.108.101.562.368 rispetto a
1.541.356.388.352. Gli aggiornamenti della cache aggiungono 56.468.266
prodotti, somme e sottrazioni ciascuno; i replay/fold originali evitati
sono distinti. Il **core coefficienti resta 751.359.028.655.932 prodotti**.
Esclusi endpoint byte, statistiche del caller, PCS, AES e risposta intera.
Nessun tempo canonico o accelerazione misurata deriva da questo screen.

## Parità e premesse

Sei test locali passano: tre della cache, coefficienti contro il riferimento
denso, pattern Booleani esaustivi e wire completa della fixture mista.
AS 2 GiB, 60 s per filtro e un worker. Nella fixture mista a otto celle,
tre programmi e wire di 14.320 B, i frame originali passano da 36 a
24/12 con budget 4 KiB/16 MiB; budget 1 B conserva 36. Il picco di heap
posseduto della fase di cella passa da 20.083 a 20.083/45.379 B. Tutte le
472 correlazioni sono consumate; wire, endpoint e transcript coincidono
con il riferimento denso accettato dal verifier originale. Restano
verificati anche il rifiuto del MAC alterato e delle configurazioni
non ammesse prima del consumo delle correlazioni.

L'identità affine segue le leggi di campo `mul_add`, `add_mul`, `sub_mul`
e `mul_sub`. Il lemma
[`lsbMle_cons`](../../lean/VoltaZk/BoundaryThinningSound.lean)
formalizza il fold affine per il suo ordine LSB; **non** raffina il mapping
MSB della cache RMS Rust. La corrispondenza con le somme Eq originali,
il raffinamento Fp3, il determinismo della sorgente e il lifetime restano
premesse implementative esplicite. Le fixture non le scaricano in generale.

La build finale di sviluppo passa in 57,040 s, RSS aggregato campionato
2.604.650.496 B, sotto 120 s/3 GiB. I controlli precedenti e la build
iniziale vengono conservati con la loro provenienza di albero modificato.
Il benchmark ignorato può ora selezionare il budget e registra l'hash
BLAKE3 della wire; non è stato eseguito sul mix completo con questa cache.

Prima della selezione servono misura rappresentativa, conto simultaneo
completo e valutazione del residuo. Nessun nuovo setup AES, processo
provider o certificato è stato avviato in questo seguito locale.
