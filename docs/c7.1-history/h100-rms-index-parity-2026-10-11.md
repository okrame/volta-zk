# RMS index — parità originale verificata

Checkout pulito `7d3ea1098053400ce40c7596d5e285186067df12`, stesso H100 e
finestra autorizzata. Tutti17 check passano, compresi30 rifiuti owner/
due successi, length/history/owner Rust, simboli obbligatori, binding/live,
fold denso e indici sparsi GPU, caller originale e produzione.
[Record immutabile](../../benchmarks/results/c71-certificates-rms-index-2026-10-11-7d3ea109.json)
SHA-256 `bfb33da5b5dbc949e66c150598045296613b6ca6bcb00178a8933bbcf2afc477`;
157 file raw, archivio15.459.823 B, manifest/hash verificati in streaming.
Il [negativo owner](h100-rms-index-owner-negative-2026-10-11.md) resta conservato.

Indici: width1/2/8/128/512,774 gate, tre programmi e due serie di challenge
incluse zero/uno.80 insiemi di coefficienti quadratici e10 terminali uguali
al riferimento sparso originale;30 allocazioni/rilasci,100 fence,280 launch,
arena56.320 B, owner42.496 B. Fisico campionato377.421.824 B e
GPU254.803.968 B, nessun incompleto. Binding/live contro denso per3/256/421
programmi e domini1..512, stesso framing byte/u16, stessi point/FS e massa
Eq con zero/uno; invalidi respinti. Nessun nuovo endpoint o correlazione.

Caller originale:28 celle vive/32 padded,93 profondità, onesto accettato
e due alterazioni respinte da RMS/PCS/P0/RNE/W/A originali; wire/FS/MAC
identici. Per caso1.210 allocazioni/rilasci,2.256 fence,10.076 launch,
H2D125.590.880 B, D2H7.601.184 B, D2D5.499.936 B, zero183.443.256 B;
arena7.693.056 B e owner42.496 B finali. Fisico campionato624.652.288 B,
GPU355.467.264 B, zero incompleti. Build Rust3.066.109.952 B fisici
campionati e GPU zero nei campioni. Nessun picco istantaneo dedotto.

CUDA SHA-256 `877debed156a5e0286b48613b22b8c2eb58664b5b785392d692c68481c6f8d2b`;
Rust oracle `15473406c962ebfcfdf61d1a517072245deaf0fcd225da2c9b4b9dfc2212f711`.
I marker del fold (84 coefficienti/24 vettori terminali) sono nei log
pubblici di entrambi i record del fold e degli indici. La
[estrazione strutturata collegata](../../benchmarks/results/c71-certificates-rms-cell-coefficient-extraction-2026-10-11-7d3ea109.json)
li aggiunge come record nuovo senza cambiare gli originali o ripetere
calcolo; SHA-256 `ab4e1f0cbe4505af362c851a06ef94d76aa15ddd681f1b8375fd9ac5374ff7db`.

Correlazioni ideali, byte/statistica GPU e159 programmi/99 profondità
ancora aperti su questa SHA. Nessun modello/setup AES, risposta canonica
o acceptance journal; zero certificati. Conto simultaneo e raffinamento
formale aperti. Contatori GPU non rappresentati da zeri dei work CPU;
H2D/D2H non misurano traffico mapped. VM solo editing/controllo/export.
