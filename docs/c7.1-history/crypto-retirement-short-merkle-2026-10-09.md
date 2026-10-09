# Lifetime PCS e helper Merkle extension — 2026-10-09

Due checkpoint locali distinti, senza CUDA, campagna hardware o ammissione
congiunta. Il percorso extension/S1 resta CPU; i consumer nativi sono in
preparazione e non sono selezionati nei source qui registrati.

## Rilascio dopo la chiusura

Source `96b69ded52c16a32962bf22c93352bd89f30c3c9`,
[record clean](../../benchmarks/results/c71-crypto-retirement-local-2026-10-09-96b69ded52c1.json),
SHA256 `eacc714846d896638e2d2e9ec0eca78deaa80b436e87d764fc11688c66cb74a8`.

`prove_schedule` tratteneva batch W e MatrixProof W durante le chiusure A.
Ora rilascia il batch dopo `close`, prima di encode, e la prova dopo
`wire.raw`; la chiusura A corrente fa lo stesso. Risultati owned e assenza
di Drop personalizzato su Batch conservano ordine close/encode/wire/FS,
MAC originali, riserva e consumo correlazioni. Il cap codec W di
470.351.872 B è un upper di capacità dei claim, non memoria effettiva
misurata o slot disponibile per altri owner.

Build fredda: 56,676 s, RSS 2.441.273.344 B, un job, deadline 60 s;
build clean calda e filtro claim passati. Il test composto ridotto di tre
attempt ha raggiunto 60 s, exit 124, RSS 171.220.992 B. Dieci artifact
originali, 42.005 B, conservano entrambi gli esiti. Nessuna nuova parità
composta o prestazione canonica segue da questa correzione.

## Hash breve e coppie in-place

Source `d16870d8ff1b49830e1225cee29dbd38db0d64f1`,
[record clean](../../benchmarks/results/c71-crypto-short-merkle-local-2026-10-09-d16870d8ff1b.json),
SHA256 `748cb82cc7a2f432bd0c7c015037799ea229e52d1d6dcf6166d7a566df3073f8`.

La foglia extension ha 160 byte: dominio, 12 limb base canonici e quattro
sali. L'ultimo blocco BLAKE3 conserva lunghezza 32. La variante paired
scrive R foglie della prima lane e poi i nodi con la seconda lane nel
medesimo output; i launch non attraversano una lane. A R23 risparmia
268.435.456 B di capacità rispetto a 2R digest, senza cambiare stream,
seek, rejection sampling, lavoro crittografico o scansioni del producer.
L'helper sali ammette R23 soltanto per geometria S1 limitata; il consumer
owner deve ancora vincolare esplicitamente i gruppi a due coset.

Due filtri Rust e un test Python passati: 12.682 foglie, 12.675 nodi
totali, 6.341 coppie, 122 bande paired, quattro regressioni a 128 colonne,
224 rifiuti canonici e due replay sparsi R23. Stream logico 405.824 B,
identico all'oracolo Rust BLAKE3 pinned; stdin/oracle/lock digest nel record.
Picco RSS dei test 283.824.128 B, massimo 11,294 s, AS 2 GiB, un worker.
Heap fixture nominato 1.892.424 B, array stack 1.056 B. I tempi host non
misurano throughput GPU. Quattordici artifact, 11.152 B, conservano anche
la precedente versione regular e il tentativo con interprete senza pytest.

Restano da verificare owner/caller S1, query extension/W, catena WHIR
completa e picchi simultanei. Ring/frontier/cursori, EQ/pad, FFT, cache,
claim/proof/codec, producer e PCG dei due ruoli restano conteggiati. La
vecchia voce certificate=128 MiB non è un bound provato di capacità:
limite wire e Vec/realloc hanno significati diversi.
