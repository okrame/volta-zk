# RMS: replay GPU delle159 ricette originali — 11 ottobre 2026

Il [record pulito `36f7dfcd`](../../benchmarks/results/c71-certificates-rms-native-replay-2026-10-11-36f7dfcd.json)
conserva il controllo concluso alle18:51:13 UTC sullo stesso pod/H100.
Passano159 programmi alle profondità GKR1/48/99, cioè replay selezionato
0/47/98. Tre pattern di liveness per programma,64 posizioni originali:
**1.431 casi e258.022.656 confronti u32** contro le wire del replay
layered Booleano originale, inclusi padding della larghezza e programmi corti.

Rust esporta piani/alias e reference originali in file esclusivi. Il
controllo GPU valida limiti, ordine degli stadi, scritture distinte,
assenza di letture nello stesso stadio, inizializzazione, liveness e EOF.
Ricostruisce12B originali dalle porte del riferimento e li passa al
producer nativo; non trasferisce righe Fp3 folded dalla CPU.
Ogni programma è provato separatamente. I momenti **misti** sono ancora
verificati soltanto dai tre piccoli circuiti del
[componente precedente](h100-rms-native-prefix-component-2026-10-11.md).

Build Rust451,341s, massimo fisico stabile campionato3.227.541.504B.
Export originali2,804/7,606/9,807s; build CUDA3,003s.
Controlli GPU0,603/1,203/1,003s, incluso il confronto CPU; massimi fisici
stabili685.821.952/690.434.048/687.136.768B. Nessun errore risorse.
Sono fixture ridotte, non tempi canonici o throughput dedotti.
Richieste device massime123.320/2.627.844/723.964B; tutti i trasferimenti
diagnostici sono riportati nel record. Nessuna capacità/owner completi.

La build CPU registra18 campioni GPU nonzero fino a556.793.856B,
alle18:45:03.867→18:45:07.972 UTC, prima delle prove GPU. Non c'è
inventario NVML in quegli istanti: **occupazione non attribuita**;
non uso del builder, isolamento o picco istantaneo dedotti.
GPU idle prima e dopo i controlli CUDA. AS CPU64GiB, figlio CUDA senza
cap AS, cap fisico6.174.015.488B e scadenze originali invariati.
Nove test documentali passano sul checkout pulito del controllo.

## Conservazione

Bundle privato `artifact/c7.1-pod/certificates-rms-native-replay01-20261011`:
47file/87.101.540B, manifest SHA256
`14e5b43d470996a2bba3c2fdf87012eb0a7a1af00d6b8b8ec8b7704c69530075`.
L'archivio conserva98 file raw/227.167.303B, inclusi entrambi i binari,
tre fixture, fonti/ricette/digest, log, monitor e terminale.
Archivio86.764.312B, SHA256
`f86f33da5d04330acca18829efc4a84e107e2d517f929b388dc310cf02ad111d`.
Ogni membro raw è riverificato in streaming contro il digest sul pod;
la VM usa buffer di1MiB per trasferimento e verifica degli artefatti.
Record SHA256
`9afcf2ed4119c78a5f546bd9553a1ec1993f433cdefb9120bc93c004ee85669e`.
I [log pubblici](../../benchmarks/results/c71-certificates-rms-native-replay-2026-10-11-36f7dfcd)
restano distinti dagli input sintetici e dai binari privati.

## Ambito successivo

La parità CPU pubblica copre tutte99 profondità; quella GPU di questo
record copre le tre indicate, separatamente per programma. Nessun credito
per fonti reali del modello, momenti misti dei159 programmi, wire/FS/MAC
o PCS completi, owner/arena comune, tail fold/core o conto simultaneo.
Prima del caller completo servono integrazione nel runtime comune,
account di host/device/trasferimenti e lavoro residuo, con validazione
del packet pubblico e dei lifetime. Premesse di distributività,
selector/mask/wire, Eq originale, count bounds/modulo, determinismo dei
frame e raffinamento CUDA ancora esplicite e non scaricate da Lean.

Pod e guard restano attivi, VM solo editing/controllo; nessun nuovo setup
AES o runner canonico. Zero certificati, O=0 incompleto, O=150/300 non
iniziati. Termine calcolo23:43:00 e hard stop12 ottobre00:13:00 UTC
immutati dal riavvio.
