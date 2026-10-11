# RMS misto: coefficienti passati e fixture wire negativa — 11 ottobre 2026

Seguito del [riavvio sul pod](h100-rms-moments-restart-2026-10-11.md).
Il [record pulito `b459b8f6`](../../benchmarks/results/c71-certificates-rms-moments-rust-negative-2026-10-11-b459b8f6.json)
conserva build647,373s e la parità dei cubici Goldilocks contro fold densi
indipendenti:1test/0,13s, tre programmi, tre profondità, punti nonbase e
zero/uno, padding e rifiuto oltre512 celle. Il nuovo percorso resta solo
`cfg(test)`, con pesatura originale per sorgente, non nativo.

## Wire: esito negativo conservato

Il test composto termina con exit101 dopo3,204s monitorati. Sul caso
onesto la wire GKR/byte, FS, MAC, endpoint e correlazioni coincidono
con il percorso originale: marker di parità,12 round prefix,84 frame,
30 prodotti di pesatura per sorgente. Questo marker **non trasforma
l'intero test in un pass**.

Il secondo input negativo della fixture (`frame(4,1,0,true)`) cambiava
un bit usato dal suo predicato Booleano. Il verifier RMS originale
respingeva già il sumcheck; il helper aspettava invece un predicato ancora
valido per arrivare alla rejection PCS originale. La correzione usa
`frame(64,1,0,true)`, cambiando il bit6 inutilizzato da quel programma
ridotto. **La correzione deve ancora essere compilata e riverificata.**
Il percorso originale e le sue regole di rejection restano invariati.

Verifiche indipendenti completate dopo lo stop del launcher:
EXP30 wire originale passa,13,009s; decoder shape/noncanonical passa;
`cargo check` della libreria produzione passa,43,026s;9 documentali passano.
Il percorso EXP30 conserva un campione incompleto. Il decoder dura meno
del periodo di campionamento e ha un solo campione incompleto, nessun
picco fisico stabile attribuibile. Questi negativi di misura restano distinti
dalle assertion aritmetiche passate.

## Risorse e ritenzione

AS CPU64GiB,1job/worker, build900s/test60s/check300s e finestra originale.
Build: massimo fisico stabile campionato3.200.667.648B,17 campioni GPU
nonzero fino a556.793.856B, alle17:30:04.692→17:30:08.154 UTC.
Nessun inventario NVML in quegli istanti: **occupazione non attribuita**,
non isolamento o uso del backend dedotto. GPU zero nei test e check;
nessun superamento risorse o errore del monitor.

Bundle privato `artifact/c7.1-pod/certificates-rms-moments04-rust01-20261011`:
90file/37.539.203B, binario36.651.568B compilato da `b459b8f6`, SHA256
`67ca763641e54fa5ee5c77dbde1a791e1253670d375d280e721cafed6a631e6a`.
Manifest SHA256
`51db29e7cf7662314237ca998beef921e89f0ab47bade7bab12ec5870a98c2ab`;
record SHA256
`12a1441d521d7fcf16a4abf7ac60b0b963379af08882c6aff8a8c0df9548bee3`.
Tutti i file del bundle riverificati; l'esito negativo rimane immutabile.

## Preparazione successiva

Il census pubblico preparato confronta il piano parallel per programma
con le wire layered originali su tre bitplane/liveness, includendo padding.
Riporta operazioni, slot shared, stadi e byte dei piani per ogni profondità,
con gate originali separati per programma. Non è una parità CUDA.

Lo screen preparato per i primi4 round usa batch4096 suffissi e chunk32
gate. Una stage delle wire originali16 posizioni resta condivisa fra tutti
i chunk; ogni chunk/batch riduce i contatori Eq e applica i pesi originali
prima di accumulare Gram e lineari per maschera. Copy e margini XOR
hanno slot separati: la posizione15 resta una wire originale, senza usare
la costante ausiliaria EXP30 al suo posto. Contare finestre host/device,
indici, stage, piani, mappe/pesi, Eq, contatori e output simultanei.

**Census e screen ancora da eseguire.** È una schedule condizionale;
non esiste ancora un caller CUDA completo. Costruzione dei piani native,
metadata/allocator, caller comune, residuo fold/core, indici/byte/PCS,
Copy/XOR instruction schedule, tempo e residenza fisica rimangono aperti.
Distributività e corrispondenza fra selector/mask/wire, determinismo
dei frame e raffinamento del nuovo builder restano premesse non scaricate.

Pod e guard restano attivi nella stessa finestra; nessun nuovo setup AES,
zero certificati canonici e nessuna selezione del runner. O=0 incompleto,
O=150/300 non iniziati; VM solo editing/controllo.
