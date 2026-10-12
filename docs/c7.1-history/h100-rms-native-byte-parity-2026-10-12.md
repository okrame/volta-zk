# RMS byte GPU — parità originale verificata sulla H100

Il [record pulito29e60a48](../../benchmarks/results/c71-certificates-rms-native-byte-2026-10-12-29e60a48.json)
passa22 controlli sul pod autorizzato, inclusi CUDA/Rust/produzione e nove
documentali. Owner byte/indici/generico e trace già passati sono riusati
con ricevute e SHA applicabili; negativi bootstrap/Werror/trace/pool
restano immutabili. Raw207 file, archivio15.967.440B, hash verificati.
Record SHA256 `ef3f75fe73122c731708dd836213f0d82d26b16095de3d7da0f8c7038abe50b9`.

348 insiemi di coefficienti e24 terminali,8 layer,3 casi,125/128 celle:
GPU mapped coincide con i figli densi originali, incluso query/challenge
zero/uno. Streaming16.377/16.384:172 coefficienti/8 terminali uguali al
consumer CPU contracted originale; checkpoint GPU massimo4 osservato,
CPU massimo5. Uno stato GPU invece di due CPU spiega la diversa geometria;
non è ammissione completa del budget. GPU890 launch,38 allocazioni/rilasci,
arena massima18.196.992B, arena finale0 ed owner42.504B.

Byte wire32 celle:13.644B/BLAKE3
`5639b87af9506540328f423e38f63f81b9acceecf72369497e09d78ab55f099c`,
457 correlazioni ideali originali, FS/MAC identici al denso CPU; leaf
alterata respinta. Callback sorgente CPU0, selezione GPU senza fallback.
Caller comune28/32/93 profondità accetta onesto e respinge due alterazioni
sui verificatori originali RMS/PCS/P0/RNE/W/A. Per caso1.247 allocazioni
e rilasci,8.929 launch, arena18.196.736B, owner42.504B dopo cleanup.

Tutte159 ricette/99 profondità,511 celle sintetiche più padding,
`native_byte:true`: wire320.320B/hash
`8782b92eb0afecba42a6aeac830933daba5e401c94c06d7b59b96cbaabdad57c`
e9.919 correlazioni ideali coincidono coi quattro CPU congelati.
Prover116,118s: cella114,001, indici0,451, byte0,730; verifier6,651s.
Una misura non accoppiata, nuovo UUID H100 rispetto alla campagna precedente:
nessun guadagno stabile o extrapolazione canonica.1.325 allocazioni/rilasci,
280.951 launch, arena110.714.112B, owner42.504B ed arena finale0.

Fisico campionato byte denso637.833.216B, streaming616.386.560B, wire
607.977.472B e caller631.660.544B; tutti zero incompleti. Nel159/99
1.272.827.904B, GPU460.324.864B e un incompleto: nessun credito al picco
stabile completo. Anche lineare native e vecchia wire hanno un incompleto.
Pool/regressioni RMS CPU osservano GPU556.793.856B non attribuiti; nessun
isolamento dedotto. Rust669,502s, RSS3.072.094.208B, GPU0; produzione
42,424s e documenti1,604s passano. GPU idle finale, processi conclusi.

CUDA SHA256 `13787250049f7c61cd9a2d43a77c539c6ffa1be25208c3318126b94cc633bb7f`;
Rust/toolchain e digest nel record. CPU AS64GiB, solo figlio CUDA senza
cap AS; fisico/arena/deadline invariati. VM solo editing/controllo/hash.
Mapped-source reads non sono contati come H2D: nessuna banda dedotta.

Byte GPU rimane opt-in sperimentale, default canonico disabilitato.
Statistica e sorgente complete, ledger simultaneo/driver, composizione
Seed6 e raffinamento restano aperti. Nessun modello o nuovo setup AES;
zero certificati canonici. O=0/journal incompleti; O=150/300 non iniziati.
La finestra di sei ore resta compute13:19:04/guard13:39:04/hard13:49:04 UTC.
