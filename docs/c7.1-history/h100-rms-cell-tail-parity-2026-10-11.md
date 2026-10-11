# RMS cell-tail — coefficienti originali e caller verificati

Checkout pulito `53d505a791433000b8ba7b2117accd661707b129`, stesso H100 e
finestra originale. Il [record immutabile](../../benchmarks/results/c71-certificates-rms-cell-tail-2026-10-11-53d505a7.json)
ha SHA-256 `8bf7b53e82087b3537c16df0fc016b4e5173445855458bd5ca298c1f29fbbd1d`.
Conservati132 file raw; archivio15.267.773 B, manifest e hash dei membri
verificati in streaming. Il [negativo dell'header](h100-rms-cell-tail-header-negative-2026-10-11.md)
resta immutabile. Tutti14 check passano: owner, trace, pool, cell-tail owner,
documenti, build CUDA/Rust, regressioni native, riferimento wire, due
parità GPU e caller, check produzione.

Il confronto denso originale copre16.377 celle vive/16.384 padded, tre
profondità e due serie di point/challenge incluse zero/uno:84 insiemi di
coefficienti nei14 round e24 vettori terminali. Ultimo round512 gruppi in
due batch, callback host frame zero.61 allocazioni/rilasci,158 fence,7.830
launch, arena massima4.590.848 B, owner finale42.496 B. Tempo wrapper1,204 s
per questo componente piccolo; un campione incompleto impedisce credito al
picco stabile/istantaneo. Non è un timing canonico o una extrapolazione.

Caller originale ridotto:28 celle vive/32 padded e93 profondità, tre
casi (onesto accettato, due alterazioni respinte). Wire/FS/MAC identici e
verificatori RMS/PCS/P0/RNE/W/A originali. Per caso931 allocazioni/rilasci,
374 fence,4.616 launch, H2D113.622.040 B, D2H7.343.568 B, zero183.361.608 B,
arena massima7.693.056 B. Fisico campionato620.478.464 B, GPU353.370.112 B,
zero campioni incompleti; non un picco istantaneo. Build Rust3.063.951.360 B
fisici campionati e GPU556.793.856 B non attribuita: nessun isolamento dedotto.

CUDA library SHA-256 `a6590cdbdeca9a368f6ccf11adb2b4fe0c3c834a2e4be71c58cdeb498ab0cfca`;
Rust oracle `ddda905f432822d830fa6f40ec58a62ce64c908d74442a737a87b8b8e7c0b83b`.
Correlazioni ideali, nessun modello/setup AES e zero certificati canonici.
Indici/byte/statistiche GPU,159 programmi/99 profondità, contabilizzazione
completa e raffinamento formale restano aperti. Contatori CPU della cella
escludono il lavoro GPU. Il checkpoint e il traffico mapped restano da
contare; nessuna selezione nel runner canonico. La VM ha solo fatto editing,
controllo e conservazione; tutto il calcolo si è svolto sul pod.
