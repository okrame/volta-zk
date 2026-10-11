# RMS — candidata GPU per i round di cella residui

Segue la [sorgente mapped verificata](h100-rms-mapped-source-parity-2026-10-11.md)
entro la stessa finestra autorizzata: calcolo fino11 ottobre23:43:00 UTC,
guard12 ottobre00:03:00 e hard stop00:13:00. Build e prove sul pod,
VM solo editing/controllo. In questo snapshot la candidata è preparata;
build e parità del nuovo fold/core non ancora validate.

Dopo i primi quattro cubici, il runtime conserva lo stesso piano
originale compilato, frame/assegnazioni, stage packed e scratch. Rilascia
Eq/aggregate dei momenti; aggiunge tre buffer privati per fold, tabelle
e gate. Il token passa da prefisso a cell-tail: gli entry point del
prefisso lo rifiutano, la sorgente rimane immutabile, altri consumer
non possono sovrapporsi. Tutti i buffer della profondità vengono
rilasciati prima di pubblicare il terminale dell'ultimo round.

Per r≥4, il gather percorre gli indici originali
`((group*16+row)*(N>>r) + side*(N>>(r+1)) + first+k)`.
Le16 righe rappresentano gli ultimi quattro bit del prefisso folded,
non righe ausiliarie. Il replay produce tutti i wire originali di tutti
i programmi nei loro stessi indici; nessun piano u32 globale.
LUT separate low/high8 sommano i pesi delle maschere Boolean16;
due metà del prefisso restante formano Eq senza divisione, anche per
challenge zero/uno. Tabelle Eq/challenge×Eq(originale) separano valori
e selector, con Eq del suffisso originale applicata prima del core.

Il core mantiene i polinomi originali And/Xor/Copy e gli stessi pesi
dei gate. Aggrega tre coefficienti pesati per programma e coppia,
poi moltiplica per il selector affine per ottenere gli stessi quattro
coefficienti. Il prover originale emette round/FS/MAC invariati; riceve
lo stesso terminale di wire e selector e continua sugli indici/byte.
Nessuna nuova correlazione, endpoint o acceptance alternativa.

Capacità delle coppie `min(source_capacity/16, 2^(cell_bits-5))`, al più256.
Fold `2*capacity*(width+programs)*24`, gate temporary
`512*capacity*3*24` e tabelle17.978 Fp3,431.472 B prima del rounding.
Scratch3.342.336 B già del prefisso riusato per aggregati/coefficients.
Owner default42.496 B (+112); point/challenge shadow1.392 B addebitata,
suffix point trattenuto nel shadow del prefisso e controllato al passaggio.
Metadati del piano e finestre host hanno shadow possedute e addebitate;
anche la pubblicazione dei momenti è trattenuta dopo un fence incerto.
Staging H2D/D2H posseduto resta vivo se il fence fallisce; capacità
incerta rimane nel conto fino al termine del processo. Il checkpoint
mapped è lo stesso, senza nuova copia completa o N×width persistente.

I test preparati comprendono22 rifiuti owner cell-tail e22 del prefisso, lunghezze/point/owner
Rust, confronto denso originale a16.384 celle per tre profondità e due
serie di challenge (incluse zero/uno),512 gruppi in due batch all'ultimo
round, e caller originale ridotto. La suite richiede la libreria CUDA
reale esplicita per le parità; gli stub del driver non fanno math GPU.

Contatori CPU `SourceCellWork` non contano le operazioni dei nuovi kernel:
zero in quelle voci non è zero lavoro GPU. Il conto completo deve includere
replay, gather mapped, tabelle, fold/core, staging, driver e tutti i lifetime.
Ancora aperti binding/live, indici/byte GPU, statistica del caller,
159 programmi/99 profondità e conto simultaneo completo. Distribuzione
MSB, LUT/fattorizzazione, selector/original wire, polinomi dei gate,
immutabilità e lifetime/fence restano premesse non scaricate da nuovi
lemmi Lean. Nessuna selezione canonica o credito al target65 s; zero certificati.
