# C7.1 — parità H100 VMM, 11 ottobre 2026

Il [record pulito](../../benchmarks/results/c71-certificates-vmm-preflight-2026-10-11-abf57c4a.json)
sulla H100 prevista usa source `abf57c4a`, CUDA 12.8 e CPU AS 64 GiB,
con soli figli CUDA senza cap AS. Build CUDA 21,818 s, test Rust 58,831 s
(profilo del pacchetto O0, dipendenze O2), runner O2 187,089 s. I risultati
di parità non sono benchmark di runtime del prover completo.

Passano quattro filtri a owner singolo: KV differito su 150/300/450 righe
con stesso handle e rifiuto del duplicato prima della copia; trasformazioni
naturali diretta/inversa; root/aperture/istogramma A; wire lineare con FS,
punto finale ed endpoint MAC originali. Tempi 0,629/1,604/10,208/20,413 s.
Cleanup riuscito e GPU idle verificata al termine, epoca 1791715988,155365.

La granularità osservata è 2 MiB: il secondo buffer A della fixture ha
131.072 B logici e 2.097.152 B fisici minimi. Il KV con 4.096 colonne
passa da 2.097.152 a 4.194.304 B senza cambiare handle o capacità logica.
Il ledger a 2 MiB è pertanto quello applicabile: le sei fasi iniziali A
rientrano nel payload; il massimo generale O=300 supera ancora il cap
nominato di 29.066.066 B. Non è una selezione per la catena completa.

Bundle privato `artifact/c7.1-pod/certificates-vmm-preflight-20261011T110000Z`,
68 file, 1.188.536 B, manifest SHA-256
`bc03645082f9e76f15130fdd382f20035058dedaec16980e71bb44f0f481e769`.
Il trial distinto `a-vmm01` parte da O=0 con cap invariati e timeout
5.400 s. Il suo risultato è pendente; nessuna root completa o certificato
è dedotta dalla parità ridotta. RMS completo resta un impedimento separato.
