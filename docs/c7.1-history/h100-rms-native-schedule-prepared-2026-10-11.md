# RMS GPU — conto del calendario implementato, preparato

La nuova candidata [native schedule](../../scripts/c71_rms_native_schedule.py)
conta le launch CUDA del percorso effettivo di prefisso/cella/indici,
utilizzando le ricette e il censimento pubblico originali. Sostituisce
solo questo conto, non il precedente screen BMMA condizionale immutabile.
Il trial misto159/99 della SHA `92afea54` è ancora in corso sul pod.

Il prefisso include gather/replay/transpose/Eq e tre launch per chunk512
di gate presenti nel supporto pubblico. Il tail comprende factors/LUT,
Eq del suffisso, gather/replay/fold per entrambi i lati di ogni finestra,
gate/somma/selector per tutti i programmi e terminale finale. Gli indici
mantengono i due lati originali, fold e riduzioni. I gruppi di prefisso
e la dimensione delle coppie cambiano con il round; nessuna estrapolazione
lineare da512 celle. Tutte le posizioni padded sono rivisitate a ogni
round del tail; accessi logici, non traffico fisico misurato.

Due controlli preparati confrontano il numero di launch con il contatore
GPU immutabile7.830 dell'oracolo denso (tre profondità, due serie di
challenge) e verificano il dominio2^29/cap256..4096. Cinque rifiuti della
geometria sono preparati. Da eseguire esclusivamente sul pod autorizzato;
nessun esito positivo attribuito prima dell'esecuzione.

Le capacità riportate sono richieste private parziali (indice e fold),
senza allocator/altri buffer/checkpoint/host staging/driver. Byte,
statistiche, FS/MAC/PCS, modello, AES, capacità simultanea e tempo
canonico esclusi. `complete_capacity:false`, `complete_work:false`,
`joint_admitted:false`, `credit:false`. Nessuna selezione canonica,
nessun lemma Lean aggiunto, zero certificati. Finestra originale e guard
immutati; VM solo editing/controllo/conservazione.
