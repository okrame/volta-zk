# RMS mapped — parità del caller originale ridotto

Il [record pulito `df8c613e`](../../benchmarks/results/c71-certificates-rms-mapped-source-2026-10-11-df8c613e.json)
conserva12 check passati sullo stesso H100/pod autorizzato: owner, trace,
pool, documenti, build CUDA/Rust, regressione lineare, sei controlli RMS,
wire CPU, wire GPU, caller GPU e check produzione. Build Rust481,642 s;
sei test RMS151,074 s. VM usata soltanto per editing, controllo e transfer
degli artefatti con buffer1 MiB. La finestra originale resta invariata.

Il caller originale ridotto usa28 celle vive/32 padded e93 profondità
native. Wire/FS/obblighi MAC uguali al riferimento CPU; caso onesto
accettato e due alterazioni respinte con RMS/PCS e P0/V/RNE/W/A originali.
Correlazioni ideali di test, nessun modello reale o setup AES.

Una registrazione del checkpoint per prova, mantenuta durante tutte le
profondità, poi retire riuscito.652 allocazioni/rilasci,281 fence,
2.193 kernel e owner42.384 B a fine prova. Arena massima7.053.568 B,
H2D113.492.584 B e D2H1.821.312 B. Le letture mapped non sono contate
da `cudaMemcpy`: questi contatori non misurano traffico PCIe/HBM totale.
Tempo caller30,014 s comprende la fixture e il confronto; nessuna
extrapolazione canonica o guadagno di latenza attribuito.

Fisico stabile campionato618.999.808 B nel caller, GPU353.370.112 B;
campioni completi ma nessuna copertura del picco istantaneo. La build CPU
osserva occupazione GPU non attribuita fino556.793.856 B; nessun isolamento
o attribuzione alla build. GPU idle prima e dopo il workflow.
Il driver simulato verifica26 rifiuti del lifecycle mapped e conserva
checkpoint/capacità quando il rilascio non è dimostrato. Test Rust su
immutabilità, owner estraneo, lunghezze, simboli mancanti e checkpoint
trattenuto dopo cleanup incerto passano; nessun credito al modello CUDA.

115 file raw,41.071.266 B, in archivio lossless15.148.023 B verificato
integralmente, manifest SHA
`ea8498a3c3d9718fc5d91728a41567040785e3860fbd16b3dc7d1dc41090e369`.
L'evidenza prepara il fold successivo; non valida fold/core completo,
indici/byte GPU,159 programmi/99 profondità o conto simultaneo canonico.
Nessuna selezione canonica e zero certificati; O=0 incompleto.
