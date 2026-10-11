# RMS: owner/CUDA passati, build Rust negativa

Il [trial pulito `88a08c6d`](../../benchmarks/results/c71-certificates-rms-common-prefix-negative-2026-10-11-88a08c6d.json)
termina alle19:42:16 UTC. Passano owner3/3, trace4/4, pool1/1 e documenti9/9.
La libreria CUDA completa compila sul pod con il nuovo consumer RMS;
SHA256 `07b9debd2e6fb1436448bac944c26c9b3dc7cf43f386c93deaf2ee0187dbd402`,
3.665.008 B. Compilazione senza esecuzione dei kernel, nessun credito GPU.

La build Rust rifiuta il nome `RmsShape` duplicato: esisteva già per il
kernel numerico; due test inoltre usavano `Arc` senza importarlo.
La nuova shape diventa `RmsPrefixShape`, mantenendo il tipo numerico
precedente; i test nominano `std::sync::Arc` esplicitamente. Queste
correzioni precedono il nuovo checkout pulito e non alterano il protocollo.
Il negativo conserva61 file/4.101.409 B, monitor, sorgente del workflow,
log e libreria CUDA. I precedenti due negativi restano immutati.

Prove GPU originali, caller/PCS e conto simultaneo ancora da completare.
La deadline originale e il guard restano invariati, stesso pod/H100.
Zero certificati canonici, nessuna nuova sessione AES o selezione canonica.
