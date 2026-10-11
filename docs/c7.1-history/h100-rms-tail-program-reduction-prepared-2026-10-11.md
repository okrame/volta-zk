# RMS tail — riduzione per programma preparata

Il [prefisso in trial](h100-rms-mixed-gate-batch-prepared-2026-10-11.md)
resta sul checkout pulito `f868468e`; questa candidata successiva non
modifica il processo o i suoi file. Il calendario verificato della SHA
`92afea54` rimane evidenza del percorso precedente, non di questa variante.

Il tail sostituisce il loop host programma/chunk/somma/selector con due
kernel per finestra di coppie. Una CTA128 per programma/coppia somma
gli stessi polinomi And/Xor/Copy pesati dei gate originali, poi applica
selector ed Eq del suffisso una sola volta. Un secondo kernel riduce
i quattro coefficienti su programmi/coppie. Il riordino delle somme
mantiene il campo originale; associatività/distributività restano
premesse di raffinamento runtime, non un nuovo lemma Lean.

Il temporaneo privato ha4×P×pair_capacity Fp3, al posto di
3×512×pair_capacity Fp3;8×P B dei range originali sono aggiunti al
buffer delle tabelle, con align allocator ancora addebitato. Una copia
H2D dei range nel primo round usa la shadow pubblica già posseduta fino
al fence positivo/close/exit. Il test owner aggiunge il suo fallimento
H2D dopo il punto, per23 rifiuti da verificare. Nessun nuovo host clone
del checkpoint, lettura del produttore o endpoint/correlazione.

Gather/replay/fold e tutte le riletture del dominio rimangono; non è un
conto completo o un'ammissione canonica. Buffer/terminali si ritirano
prima della pubblicazione come nel percorso originale. Le vecchie
funzioni private non più chiamate vengono eliminate. ABI/token e
verificatori originali invariati; default canonico non seleziona la GPU.

Owner/Rust, coefficienti densi84/24, indici80/10, caller con alterazioni
respinte e159/99/wire devono passare sul pod prima di attribuire risultati.
Zero certificati, byte/statistica GPU, capacità fisica simultanea, modello,
PCS e real/AES aperti. VM solo editing/controllo; calcolo23:43:00 UTC,
guard00:03:00, hard stop12 ottobre00:13:00, stessa autorizzazione.
