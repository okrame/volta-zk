# RMS tail — riduzione per programma verificata

Checkout pulito `c0e0448d4ddb424736fffcf6731ffacd5b91d3bd`,18 check passati.
Il [record](../../benchmarks/results/c71-certificates-rms-tail-reduce-2026-10-11-c0e0448d.json)
ha SHA-256 `345af777c7e105708d5dd1cc9e64fbc2b31ed6dd9b7ac667513397ad0bdbc69f`;
168 raw, archivio15.409.785 B, manifest/hash verificati in streaming.
Passano23 rifiuti owner del prefisso e23 del tail,32 degli indici,
regressioni native, binding/live originale e produzione. Il test owner
tail include il nuovo fallimento H2D dei range dopo il punto originale.

Gli84 coefficienti/24 terminali densi originali passano su16.384 celle,
tre profondità e due casi di challenge, inclusi zero/uno;4.512 launch
contro7.326 del [batching prefisso](h100-rms-gate-batch-parity-2026-10-11.md).
Passano anche80 coefficienti/10 terminali degli indici. Nessun callback
host frame. Queste piccole ricette non isolano stride oltre128 gate o
chunk oltre512: la fixture ragged preparata li verifica separatamente.

Il159/99 usa gli stessi511 campioni nonzero Integer RMS/512 padded,
verificatore originale GKR/FS/MAC,9.919 correlazioni ideali e wire320.320 B
con BLAKE3 `8782b92eb0afecba42a6aeac830933daba5e401c94c06d7b59b96cbaabdad57c`:
uguale a tutti i quattro CPU congelati. Launch280.299, prover113,559 s,
cella111,234 s, indici0,419 s, byte CPU0,884 s, altro1,022 s;
verifier6,500 s. Questa è una singola misura; AB/BA avviato separatamente
con i due binari già congelati, nessuna build durante il confronto.

Arena110.714.112 B,1.288 allocazioni/rilasci, owner42.496 B e arena finale0;
H2D7.279.525.676 B, D2H17.376.096 B, D2D5.955.744 B. Fisico campionato
1.272.451.072 B/GPU458.227.712 B, zero incompleti nel159/99. Coefficienti
tail/indici, owner tail e pool hanno ciascuno un campione incompleto;
nessun credito al loro picco stabile o al picco istantaneo completo.

Caller originale RMS/PCS/P0/RNE/W/A: onesto accettato, due alterazioni
respinte, stesso wire/FS/MAC. Per caso1.210 allocazioni/rilasci,
arena7.656.704 B,8.469 launch; fisico campionato622.166.016 B,
zero incompleti. Cleanup positivo e GPU idle ai bordi del workflow.
CUDA SHA-256 `b2bbefdba697ee1a5142998058f59834bd574b6a86dc01d501512ede700f06ad`;
Rust invariato `3a68dec0a8b16252b4cf42f1a65362ae645d6f2a60102b4967d33cced8e2b0e0`.
Cargo cached0,201 s non è una nuova build completa.

Le due riduzioni per finestra conservano gli operatori e selector
originali; associatività/distributività, geometria, lifetime dei range,
raffinamento CUDA e allowance driver restano premesse non scaricate.
Byte/statistica GPU, modello, real/AES, PCS sul159/99 e conto simultaneo
restano aperti. Zero certificati canonici/journal; nessuna extrapolazione
del target65 s. Pod RUNNING durante la preparazione; VM solo controllo,
editing e verifica streaming. Termine calcolo23:43:00 UTC, hard stop
12 ottobre00:13:00 UTC, finestra originale invariata.
