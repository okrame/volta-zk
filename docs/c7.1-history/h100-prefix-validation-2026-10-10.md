# H100: validazione del prefisso originale — 10 ottobre 2026

Il [record](../../benchmarks/results/c71-h100-prefix-2026-10-10-47af19bbe888.json)
valida la checkout pulita `47af19b`, pubblicata e ricevuta tramite Git HTTPS.
La build dei test Rust impiega 444,984 s, RSS 2.897.702.912 B; la libreria
CUDA sm_90 viene ricompilata in 21,411 s. Passano i 15 test sulla libreria
reale e il controllo non lineare. Le fixture aggiornate verificano radici,
aperture, residual e closure lineare/MAC originali con capacità tripla
rispetto al prefisso scritto. I rifiuti della coda e degli span fuori limite
sono coperti dalla [regressione locale prima/dopo](h100-prefix-candidate-2026-10-10.md).

Il binario canonico Rust `3ea1e4a` viene riusato: il confronto delle sorgenti
conferma che le sole differenze Rust appartengono ai moduli di test.
La libreria nuova ha SHA-256
`ac65f259b2fd3befefbe132039167a1b6159961dbc5018138981d5b300bed91f`.
Stack 256 B, code CUDA 1/1 e input sigillati restano invariati.
Questa validazione finita non misura un commitment A completo, una risposta
o il picco simultaneo completo; `credit:false`.

Il bundle privato `h100-final-prefix-validation-20261010T003700Z` conserva
148 file/4.042.909 B, manifest SHA-256
`93276984134989d9fef6e3f9a9fb8246326863a39ea6e7efc07eb14d8b12bcd5`.
Tutti gli hash sono riletti dopo il trasferimento; i precedenti manifest
rimangono immutati e collegati dalla provenienza.
