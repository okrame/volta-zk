# C7.1 — prodotto RMS agli estremi, 11 ottobre 2026

Per le righe già foldate il coefficiente incrociato del prodotto è ora
`hi_x*hi_y - x*y - dx*dy`. È identico a `x*dy + dx*y`; usa tre prodotti
per il polinomio quadratico, anziché quattro. AND/XOR pesati passano da
sette a sei prodotti Fp3; Copy e il primo round Booleano non cambiano.
L’identità è distributività nel campo (`mul_add`, `add_mul`, `sub_mul`,
`mul_sub`); non è un nuovo raffinamento Lean dell’implementazione Fp3.
Le tre celle del polinomio sono riusate, nessuna nuova allocazione.

Passano le regressioni su tutti i pattern Booleani, coefficienti contro
fold densi e wire/FS/punto/endpoint MAC originali nella fixture mista.
Quest’ultima confronta la prova completa serializzata con il prover denso
e respinge anche la modifica del tag terminale. Passano 22 test Python,
inclusi il conto selezionato contro quello storico per O=0/150/300.
Build locale 58,544 s, RSS aggregato campionato 2.618.732.544 B, entro
120 s/3 GiB; le tre invocazioni Rust rispettano 60 s/AS 2 GiB.

Il core con supporto originale passa da 844.006.203.160.300 a
751.359.028.655.932 prodotti per risposta: −92.647.174.504.368 (10,98%).
Questo conta soltanto il core dei coefficienti; callback, replay, fold,
PCS, setup AES e altri componenti restano esclusi. Non risolve il costo
completo e non concede tempo o selezione canonica. La misura rappresentativa
su 159 ricette/512 celle è preparata separatamente dalla variante A attiva.

Il bundle preliminare privato è
`artifact/c7.1-pod/certificates-rms-endpoint-local-20261011T114500Z`.
Build e verifiche precedono il commit; il primo census è privo di wrapper
esplicito AS/timeout e non costituisce evidenza di risorse. Il successivo
record pulito deve rieseguirlo entro i limiti. Zero certificati canonici.
