# RMS index — token respinto dopo il primo upload

Il [record immutabile del checkout `7ba70443`](../../benchmarks/results/c71-certificates-rms-index-negative-2026-10-11-7ba70443.json)
conserva19 file/26.321 B. Compilazione C++ owner riuscita; il caso onesto
fallisce al primo round perché il buffer privato del token non ha coverage
initialized, pur avendo completato upload e fence. Nessuna build Rust o
prova GPU eseguita in questo trial. SHA-256 del record
`b848581637743ca95237a46543e82f4308b9f0d5d23ea1a75808cbee496808a5`.

La correzione marca i tre buffer completi dopo il fence riuscito, prima
della pubblicazione del token. Non allenta il check della capability.
Il driver diagnostica fault/error se il caso onesto fallisce di nuovo.
Nuovo checkout e directory, stessa finestra e hardware autorizzati.
VM solo editing/controllo; zero certificati, nessun credito di parità.
