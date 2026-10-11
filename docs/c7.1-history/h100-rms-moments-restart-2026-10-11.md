# Riavvio per il backend RMS misto — 11 ottobre 2026

Il proprietario chiede perché il [confronto byte](h100-rms-byte-paired-2026-10-11.md)
è stato seguito dallo stop del pod e ricorda che la VM ha poche risorse.
L'agent aveva applicato lo stop anticipato del piano pretrial dopo il
confronto, lasciando aperto il backend completo. La nuova istruzione
`ok autorizzo a riparire lo stesso pod` autorizza il riavvio e sposta
preparazione computazionale, test e build sul pod; la VM serve per editing
e controllo. Non estende hardware, durata o protocollo.

## Riavvio e finestra

Stesso pod `z6wx2kkn69eoc0`, resume confermato alle17:05:42 UTC. Guard
indipendente PID27013/start ticks332392984, pronto prima della mutazione
provider. La finestra originale resta11 ottobre16:13:00.494→12 ottobre
00:13:00.494 UTC: compute end23:43:00.494, stop guard00:03:00.494.
Le nuove date `lastStartedAt` del provider non azzerano quella finestra.

Proxy SSH autenticato con chiave dell'owner e host gateway già conosciuto;
nuova chiave host letta da `/etc/ssh/ssh_host_ed25519_key.pub` prima
dell'accesso diretto, ora porta17234. Container `0ff89269c4c9`, workspace
vuoto ed effimero. H10080GB, UUID `GPU-e05e977b-758d-f3f4-cbe8-5720b83d1ae1`,
81559MiB, driver580.126.09; zero memoria GPU e processi compute all'accesso.
CPU28vCPU/RAM251GiB, disco230GB. Checkout anonimo Git HTTPS pulito
`f25452bf56cd36ebb3a77dd8386bca53959eadc2`; credenziali rimaste sulla VM.

## Controlli sul pod

Il [record immutabile di avvio e controlli](../../benchmarks/results/c71-certificates-rms-moments-start-2026-10-11-f25452bf.json)
conserva tre test F97 del prefisso misto passati in3,66s, nove documentali
passati e lo screen pubblico della geometria. AS CPU64GiB/un worker,
timeout60s/step, monitor component e cap fisico6.174.015.488B. Picchi
fisici campionati rispettivi86.908.928/59.449.344/69.083.136B; GPU zero
in tutti i campioni, nessun campione incompleto o errore di risorsa.
Sono misure di componenti, non picchi completi o certificati.

Il primo controllo documentale ha1 failure/8pass perché nove Markdown
di ricerca ignorati da Git mancavano nel container vuoto. Conservati
stdout/stderr e summary negativi. Copie selezionate degli input originali,
1.148.928B, trasferite privatamente con SHA256 riverificati; poi nuovo
label e9pass. Nessun file originale o esito sovrascritto.

Bundle privato `artifact/c7.1-pod/certificates-rms-moments04-start-20261011`:
51file/50.931B, manifest SHA256
`81356a50420b6a695bfae2461b5d19c5ec0f6f20d4a199ef668ae79fe363997b`.
Record pubblico SHA256
`e277f3e35fb93cc3d55111a134aa38b5d6d3d6313d57b91112f269f3905900f1`.
Guard e pod restano attivi per il lavoro successivo nella stessa finestra.

## Parità Rust in preparazione

Il nuovo oracolo è solo `cfg(test)`, rifiuta domini oltre512 celle e
applica i pesi originali per ciascuna sorgente. Usa il replay packed
esistente e momenti16×16 più16 termini lineari per maschera pubblica.
La maschera limita il selector; le wire di altri programmi restano tutte.
Gli stessi selector e fold MSB alimentano i cubici originali, senza accesso
a nuove sfide o correlazioni. Il valutatore condivide il percorso momenti
esistente; il decoder EXP30 a15 posizioni conserva la sua geometria.

Sono preparati i filtri `c71_b12_mixed_prefix_goldilocks_coefficients_keep_other_program_wires`
e `c71_b12_mixed_prefix_four_rounds_original_wire_and_mac`: coefficienti
contro fold densi indipendenti, punti zero/uno/nonbase e parità della wire
GKR/byte/FS/MAC con PCS originale su tre programmi ridotti, profondità
diverse e padding. **Build ed esecuzione ancora pendenti**, da svolgere
sul pod. Le capacità nominate dell'oracolo non contano BTree/allocator e
non ammettono il builder completo o un tempo canonico.

Restano aperti il builder nativo a blocchi con pesatura tardiva, conto
di replay/fold/residuo/traffico e lifetime simultanei, parità CUDA e
raffinamento Lean. Zero setup/sessioni AES nuove e zero certificati
canonici; O=0 incompleto, O=150/300 non iniziati. Le candidate canoniche
restano disabilitate.
