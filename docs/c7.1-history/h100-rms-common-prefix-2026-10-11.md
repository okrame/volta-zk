# RMS: caller GPU comune ridotto, 11 ottobre 2026

Il [trial pulito `c67db510`](../../benchmarks/results/c71-certificates-rms-common-prefix-2026-10-11-c67db510.json)
termina alle19:55:56 UTC sullo stesso pod/H100. GPU idle prima e dopo;
guard e deadline originali invariati. Tutta la compilazione e le prove si
svolgono sul pod; la VM conserva l’archivio con buffer da1 MiB.

Il prefisso a4 bit usa sette buffer privati nell’arena del medesimo owner
del caller. Il piano resta sul device durante una profondità; frame12B e
assegnazioni passano in finestre limitate. Le sezioni coprono il supporto
compilato dalle tile originali. Maschere selezionano soltanto i selector;
wire degli altri programmi e riga15 mantengono le posizioni originali.
Eq usa gli indici del suffisso originali. Chunk512, conteggi nei registri,
momenti Fp3 fusi per maschera. Fence e free riusciti precedono il risultato;
host metadata/validator/publicazione sono addebitati, free incerte trattenute.

Passano due fixture GPU, ognuna nei casi onesto e due alterazioni:

| Prova | Geometria | Verifica |
|---|---|---|
| RMS misto/GKR/PCS |32 celle, tre circuiti piccoli,3 profondità | wire/FS/MAC uguali al CPU; verificatori RMS/PCS originali |
| Caller Gemma RMS |28 vive/32 padded, matrici PCS32,93 profondità native | statistiche, P0, V, RNE e radici W/A originali; wire/FS/MAC uguali al CPU |

I casi onesti sono accettati; quelli alterati sono respinti nel flusso
originale. Non c’è acceptance sostitutiva. Le correlazioni sono righe ideali
di test, senza setup AES reale, pesi/modello originali o certificato canonico.
Il caller è ridotto: non prova momenti GPU dei159 programmi canonici/99
profondità o capacità simultanea con i relativi owner.

Per ciascuna delle tre prove del caller:651 allocazioni e651 rilasci,
2.100 kernel,279 fence, H2D118.825.192 B, D2H1.821.312 B, memset60.487.296 B.
Owner host42.280 B; arena massima7.053.056 B, zero alla fine, nessun errore
di cleanup. Questi contatori di API non sono traffico HBM misurato.
Il consumer RMS piccolo usa21 allocazioni/rilasci,72 kernel e arena3.513.344 B.

| Fase monitorata | Tempo totale | Massimo fisico campionato | Campioni incompleti |
|---|---:|---:|---:|
| Build Rust |482,433 s |3.039.289.344 B |1 |
| RMS GPU/PCS |8,485 s |601.116.672 B |1 |
| Caller GPU |29,970 s |613.847.040 B |0 |
| Check produzione |12,210 s |1.230.237.696 B |0 |

Build:2.411 campioni GPU tutti zero. Nessuno di questi massimi dimostra
il picco istantaneo o l’allowance canonica. CPU AS64 GiB, figli CUDA senza
cap AS con ricevute; limiti fisici/arena/deadline conservati.

Passano owner3/3 (inclusi19 rifiuti RMS), trace4/4, pool1/1 e documenti9/9
su `88a08c6d`; sorgenti CUDA/driver invariati verificati prima del riuso.
Sul nuovo checkout: check produzione, regressione lineare, simboli lineari,
due controlli Rust di capability/simboli RMS, wire mista CPU e due prove GPU.
Libreria CUDA3.665.008 B, SHA256
`07b9debd2e6fb1436448bac944c26c9b3dc7cf43f386c93deaf2ee0187dbd402`;
Rust36.938.992 B, SHA256
`ed80699b2b7b2cb0dd55f1939258d61d8a80f9e47eed4ece08a89f9b33da907b`.

Tre negativi iniziali restano conservati:
[cleanup C++](../../benchmarks/results/c71-certificates-rms-common-prefix-negative-2026-10-11-369636be.json),
[attese di dimensione](../../benchmarks/results/c71-certificates-rms-common-prefix-negative-2026-10-11-a324ebf3.json),
[binding Rust](../../benchmarks/results/c71-certificates-rms-common-prefix-negative-2026-10-11-88a08c6d.json).
Le correzioni precedono il checkout pulito della prova positiva.

Conservati92 file grezzi/41.365.290 B nell’archivio lossless15.120.075 B;
tutti i membri sono verificati per hash con buffer da1 MiB. SHA256 archivio
`5795c9dc957857d2b1e251f76a3dc05c33bec9cb46389f13f6d66801e2eb6cbc`,
manifest `08ca5bb21a631a427185308da1caea895c8c3371a0c3dbdb77b212a5ab32b5c4`.
Un receipt separato registra le correzioni di parsing/pubblicazione dei
metadati; record e manifest grezzi non vengono riscritti.

Restano premesse runtime non scaricate: raffinamento del DAG parallelo,
supporto compilato, selector/mask/wire, momento/ricostruzione/count bounds,
Eq originale, determinismo, lifetime e capacità. Nessun nuovo lemma Lean.
Il piano chunk32 storico non descrive questa implementazione fused512.
Il conto completo deve includere anche Eq diretto, replay/trasferimenti,
buffer/Vec e transitori, fold/core residuo e indici/byte originali.
Zero certificati canonici, O=0 incompleto, O=150/300 non iniziati.
