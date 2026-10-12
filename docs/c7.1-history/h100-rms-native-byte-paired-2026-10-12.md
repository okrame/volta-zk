# RMS byte GPU — confronto AB/BA sullo stesso owner

Il [record pulito416a48c3](../../benchmarks/results/c71-certificates-rms-native-byte-paired-2026-10-12-416a48c3.json)
conserva A1/B1/B2/A2 con identici CUDA/Rust congelati29e60a48 e stessa
H100/UUID. A usa byte CPU contracted, B byte GPU, cella/indici identici;
nessuna build o altro calcolo concorrente, GPU idle ai bordi. Identità
code29e60a48→416a48c3 verificata, nuove process/owner per prova. Nove
controlli documentali passano sul checkout416a48c3. Tutte le wire320.320B,
hash e9.919 correlazioni coincidono coi quattro CPU originali.

Media prover116,077→115,447s, riduzione osservata0,5433%, più piccola della
variazione fra ripetizioni: nessun guadagno end-to-end stabile attribuito.
Endpoint byte0,881695→0,722790s, riduzione osservata18,0226%. Medie e
rapporti calcolati sul pod. Sono componenti512/159/99 con input sintetici
e correlazioni ideali, esclusi modello/statistica/PCS/AES/risposta.

A1 ha occupazione GPU fino900.726.784B, aggiuntiva non attribuita rispetto
ai460.324.864B delle altre prove; conservata nel conto, nessun isolamento
inferito. B1/A2 hanno un campione incompleto ciascuno; nessun picco stabile
completo o istantaneo.65 file e archivio284.216B, hash verificati;
record SHA256 `70ef465754b66a04bdd83eed3a65a62f4999c4a6b5b1fee466740c641cc1c30b`.

Byte resta opt-in sperimentale. Statistica e dispatcher canonico ancora
CPU, backend completo e conto simultaneo/driver aperti, zero certificati.
Il seguito prepara il consumer statistica sullo stesso P0 originale,
senza cambiare FS/MAC o default prima delle verifiche. La finestra
compute13:19:04/guard13:39:04/hard13:49:04 UTC non si sposta.
