# RMS byte GPU — checkpoint host/CUDA, matematica pendente

Il [record pulito29e60a48](../../benchmarks/results/c71-certificates-rms-native-byte-build-checkpoint-2026-10-12-29e60a48.json)
conserva soltanto artefatti chiusi del trial byte06; build Rust ancora viva
al checkpoint, nessun suo risultato ammesso. Owner byte/indici/generico
e trace già passati sono riusati con ricevute esplicite e identità
delle sorgenti applicabili; nessuna riscrittura dei negativi.

Pool14 scenari e tail23 rifiuti passano; owner pool42.576B confermato.
Tempi15,263/14,754s; fisico campionato949.682.176/392.232.960B. Durante
il test CPU del pool il monitor osserva556.793.856B GPU non attribuiti,
conservati nel conto, senza inferire isolamento o credito GPU. Tail
registra GPU0; entrambi zero campioni incompleti, nessun picco istantaneo.

Toolchain Rust1.96.1 installata e dipendenze locked scaricate sul pod.
NVCC12.8.93/sm90 compila tutti i16 sorgenti, incluso byte, in28,420s;
fisico campionato249.663.488B/GPU0, zero incompleti. Libreria4.545.464B,
SHA256 `13787250049f7c61cd9a2d43a77c539c6ffa1be25208c3318126b94cc633bb7f`.
48 file preservati con hash, archivio1.914.010B e manifest privato.
I kernel byte hanno stack massimo216B nella build, da correlare alla
configurazione runtime256B; non è un bound simultaneo o di driver.

Restano verifiche Rust/API, coefficienti/figli originali degli8 layer,
checkpoint realmente osservato, wire/FS/MAC e caller RMS/PCS, poi159/99.
Nessuna aritmetica byte GPU o selezione canonica ammessa dal solo linking.
Modello, statistica, ledger completo, PCG AES, O=0/certificato/journal e
O=150/300 sono ancora aperti. VM solo editing/controllo/hash streaming;
compute end13:19:04/guard13:39:04/hard stop13:49:04 UTC invariati.
