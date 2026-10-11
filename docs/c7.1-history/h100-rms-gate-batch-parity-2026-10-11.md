# RMS prefisso — batching originale verificato

Checkout pulito `f868468ed05d6822e9d41206023f62afaacc6591`,18 check passati,
inclusi23 rifiuti owner del prefisso/32 degli indici, regressioni Rust,
coefficiente denso84/24 e indici sparsi80/10, caller originale,159/99 e
produzione. Il [record](../../benchmarks/results/c71-certificates-rms-gate-batch-2026-10-11-f868468e.json)
ha SHA-256 `f3117f7ce90661f3b2f054a24ed31e6a73ea5480290e38f3af86cb4e6df9b834`;
168 raw e archivio15.405.429 B, manifest/hash verificati in streaming.

Stessi511 campioni nonzero Integer RMS/512 padded,159 ricette/99
profondità. GKR/FS/MAC originale,9.919 righe ideali e stesso wire320.320 B/
BLAKE3 di tutti i quattro CPU e del [trial GPU precedente](h100-rms-mixed-all-parity-2026-10-11.md).
Le launch787.599→707.364 diminuiscono; una sola misura prover126,808 s
contro124,478 s precedente non mostra miglioramento di tempo e non è
un confronto temporale controllato. Cella124,494 s, indici0,446 s,
byte CPU contracted0,890 s, resto0,978 s; verifier6,567 s.

Arena111.058.432 B,1.288 allocazioni/rilasci, owner42.496 B e arena finale0;
H2D7.279.399.748 B, D2H17.376.096 B, D2D5.955.744 B. Il nuovo piano
pubblico è addebitato e sopravvive ai fence incerti. Fisico campionato
1.272.659.968 B/GPU460.324.864 B, un incompleto: nessun credito al picco
stabile/istantaneo o al conto simultaneo canonico.

L'oracolo denso16.384 celle/tre profondità/due challenge ha7.326 launch,
stessi84 coefficienti/24 terminali, zero callback host. Caller originale
28/32 celle/93 profondità, RMS/PCS/P0/RNE/W/A: onesto accettato e due
alterazioni respinte, stesso wire/FS/MAC;1.210 allocazioni/rilasci per
caso, arena7.693.056 B,9.776 launch, H2D125.595.344 B. Fisico campionato
622.706.688 B, zero incompleti. CUDA SHA-256
`d61c935a64b5646d69740530d6f958b3c65cd32d0312e24a7e2afd30abde3ccb`;
Rust oracle invariato `3a68dec0a8b16252b4cf42f1a65362ae645d6f2a60102b4967d33cced8e2b0e0`.
Cargo conferma il binario già compilato in0,201 s: non è una nuova build
completa. GPU zero nei campioni del controllo Cargo.

La [riduzione tail](h100-rms-tail-program-reduction-prepared-2026-10-11.md)
è ora in trial separato su `c0e0448d`, finestra/guard invariati. Preparato
un [conto delle candidate batch](../../scripts/c71_rms_batched_schedule.py):
tre controlli, due confronti coi contatori GPU conservati e invarianti
delle riletture. Da eseguire sul pod; nessun nuovo conto canonico ammesso.

Byte/statistica GPU, modello/PCS/real-AES, capacità completa e
raffinamento aperti. Nessun certificato/journal canonico. Il byte resta
CPU32 MiB; nessuna extrapolazione del target65 s. Pod RUNNING, VM solo
editing/controllo/verifica artefatti, calcolo23:43:00 UTC e hard stop
12 ottobre00:13:00.
