# H100: W e setup completi del sesto trial — 10 ottobre 2026

Il [record](../../benchmarks/results/c71-h100-setup06-checkpoint-2026-10-10-47af19bbe888.json)
congela le fasi concluse di `canonical-06` mentre O=0 continua. Checkout
pulita `47af19b`, binario Rust `3ea1e4a`, libreria CUDA `47af19b`; input,
Γ ammesso, stack 256 B e code 1/1 verificati. W, setup e journal sono
nuovi: nessuna correlazione o stato terminale è riutilizzato.

| Fase | Tempo completo |
|---|---:|
| Caricamento packed W | 61,543 s |
| Residenza nativa W | 22,723 s |
| PCS W | 190,425 s |
| Installazione W, PCS inclusa | 212,418 s |
| Setup verificatore | 1.493,833 s |
| Setup prover, simultaneo al verificatore | 1.493,832 s |

PCS W è vicina ai 190,200 s del quinto trial; il caricamento, che allora
richiedeva 322,159 s, varia sensibilmente e va contato separatamente.
Il massimo temporaneo stabile campionato nella fase W è 4.301.045.248 B.
Questo checkpoint non misura il picco completo della risposta.

Il setup precedente impiegava 1.986,453 s. Con frame incrementale e
coda cGGM differita il nuovo setup risparmia **492,620 s**, pari a
**24,799%** e **1,32977×** osservati. Il microbenchmark del solo componente
misurava 1,475×. Si confrontano run singoli con correlazioni fresche;
l'ultimo minuto circa del setup precedente si sovrapponeva a un build/test
CPU indipendente. Il confronto non isola causalmente ogni contributo.
I log confermano la ricompilazione `volta-pcg` nel binario `3ea1e4a`.

Il traffico applicativo del setup è invariato: **61.841.366 B nei due
sensi**. Slot SHAKE, scarti, frame, capacità e contratti restano identici;
non viene riusata la casualità. La parità finita e il guadagno osservato
non chiudono il raffinamento generale Seed6/CUDA o il bound della risposta.
Non sommare i due intervalli simultanei P/V o PCS e installazione inclusiva.

Due bundle verificati conservano soltanto snapshot chiusi:
`h100-final-W06-checkpoint-20261010T005900Z`, 4 file/240.131 B, manifest
`f2891b4d9a819be5680fa19ae96f9d629670c3ab50312cec2857addf5fc683f2`;
`h100-final-setup06-checkpoint-20261010T011200Z`, 3 file/15.768 B, manifest
`f4d5cbb7916e84397ec975e9413b4b29715b1518462cc77bcf602ad06651b693`.
Il primo helper setup cercava un evento annidato come evento diretto e
terminava con `StopIteration` prima di scrivere; il record conserva
l'errore operativo e la selezione corretta, senza alcun effetto sul trial.
A questo checkpoint nessun A completo o certificato è acquisito.
