# RMS — checkpoint originale leggibile dalla GPU

Il proprietario ha autorizzato il riavvio dello stesso pod
`z6wx2kkn69eoc0`; finestra originale16:13:00–00:13:00 UTC, calcolo
fino23:43:00 e guard00:03:00. VM solo editing/controllo, build e prove sul pod.

La [calibrazione](../../benchmarks/results/c71-certificates-rms-source-map-calibration-2026-10-11-7fcf2f60.json)
sul checkout pulito `7fcf2f60` osserva supporto per registrazione host,
mapping e sola lettura, flag device8; register/device-pointer/unregister
e close del runtime comune restituiscono0. Nessun kernel eseguito.
Il primo tentativo fallisce con exit127 perché `nvcc` non è nel PATH;
il secondo usa il percorso assoluto. Entrambi conservati nello stesso
nuovo archivio verificato:30 file,360.418 B compressi, manifest separato.
Un campione incompleto nel query; nessuna copertura del picco istantaneo.

La candidata successiva mantiene un solo checkpoint CompactFrames
immutabile, ora `Arc<Vec<u8>>`. Il runtime trattiene un riferimento prima
della registrazione, fino a retire/close riuscito. Se unregister fallisce
non lo ripete; se close non dimostra cleanup, conserva il riferimento e
la capacità allocata fino all'uscita del processo. Il programma termina
il tentativo. Non prosegue né rimborsa ownership incerta.

Il packet pubblico conserva le norm originali e gli stessi tile dyadici
ordinati del caller: norm48 B, tile32 B, shape32 B. Validazione di offset
P/S/Y, copertura completa, partizioni dyadiche, ordine/assenza di duplicati,
programmi e dominio. La GPU ricostruisce gli stessi frame10/12 B dal P/S/Y
originale: statistiche6 B condivise per riga, padding zero, assegnazioni
originali, senza tabella N-entry o seconda copia completa del payload.
Il prefisso usa ancora replay, Eq, momenti e verificatori originali.

Il mapping usa `cudaHostRegisterMapped | cudaHostRegisterReadOnly` e il
device pointer restituito; supporti assenti o errori CUDA sono terminali.
Le [regole NVIDIA CUDA12.8](https://docs.nvidia.com/cuda/archive/12.8.0/cuda-runtime-api/group__CUDART__MEMORY.html)
richiedono il supporto della sola lettura e la deregistrazione della
stessa base. La query finita sul pod non prova questi comportamenti su
altri runtime o tutto il raffinamento Rust/CUDA.

Owner default42.384 B (+104), trace42.416/42.424 B e pool42.456 B.
Un buffer privato arena per metadati sorgente, separato dai sette buffer
del prefisso per profondità. Shadow host allineata delle norm/tile e
metadati device addebitati; slack di arrotondamento delle pagine host
addebitata prima di register. Il payload Rust è già nel census globale,
contato una sola volta; Arc aggiunge40 B heap, con Vec/counter originali.
Il conto precedente RMS5.028.218.943 B non include questi nuovi lifetime:
conto simultaneo e allowance driver da rivalutare, nessuna ammissione.
Letture mapped non compaiono nei contatori `cudaMemcpy` H2D; nessuna
deduzione di traffico PCIe/HBM da quei soli contatori.

La candidata è preparata ma build/parità non ancora validate in questo
snapshot. Fold/core dopo i primi quattro round, indici/byte, tutti159
programmi/99 profondità e conto completo restano aperti. Distributività,
corrispondenza di tile/frame/selector, immutabilità, lifetime e fence
sono premesse implementative non scaricate da nuovi lemmi Lean.
Nessuna selezione canonica o setup real/AES: zero certificati.
