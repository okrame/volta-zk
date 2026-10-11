# H100 RMS byte — confronto AB/BA e chiusura, 11 ottobre 2026

La [nuova autorizzazione e l'avvio](h100-rms-byte-start-2026-10-11.md)
seguono il [piano pretrial](h100-rms-byte-followup-plan-2026-10-11.md).
Sorgente pulita `30867b9b4d000943d25daacc816367b9b7435a03`, Rust1.96.1,
build opt2/un job/un worker, CPU AS64 GiB, cap fisico6.174.015.488 B.
La fixture esegue tutte le159 ricette originali e99 profondità su511
celle sintetiche vive più padding. Il DV GKR originale accetta ciascuna
fixture con FS/MAC originali e9.919 correlazioni ideali consumate.
**Zero certificati canonici**: esclusi modello, statistiche del caller,
PCS, AES e risposta completa. O=150/300 non iniziati.

## Confronto nello stesso binario

[Record immutabile](../../benchmarks/results/c71-certificates-rms-byte-paired-2026-10-11-30867b9b.json),
SHA256 `6f6c98968ade72bd719133411d9d6e5848fb16057167d094f3a4f276b7dcd7a9`.
Cache16 MiB e gate condivisi comuni; byte contraction0/1/1/0, timeout600 s.

| Prova | Byte | Prover s | Cella/replay s | Indici s | Endpoint byte s | Verifier s |
|---|---:|---:|---:|---:|---:|---:|
| A1 | 0 | 156,877 | 70,421 | 76,023 | 10,105 | 6,633 |
| B1 | 1 | 147,388 | 70,127 | 76,045 | 0,899 | 6,558 |
| B2 | 1 | 147,756 | 70,556 | 75,984 | 0,881 | 6,512 |
| A2 | 0 | 156,113 | 69,981 | 75,868 | 9,943 | 6,559 |

Media prover156,4947846475→147,5719109505 s: −5,70170675% osservato.
Media endpoint10,0236666145→0,8902936985 s: −91,11808350%.
Le fasi cella/indice non si riducono; i cronometri includono replay/fold,
FS/MAC e preparazione dei rispettivi piani. La somma delle tre fasi più
il residuo coincide esattamente con `prove_ns` in tutte le prove.
Sono due coppie, senza stima statistica o trasferimento al dominio canonico.

Tutte le wire320.320 B hanno BLAKE3
`8782b92eb0afecba42a6aeac830933daba5e401c94c06d7b59b96cbaabdad57c`,
uguale anche al riferimento storico. È confronto di hash della wire
completa, non conservazione/comparazione byte per byte della risposta
canonica. I byte effettivi di certificati/accettazioni canonici restano assenti.

Le letture di frame dell'endpoint scendono30.985.128→97.056; letture byte
originali della contrazione98.112, righe rigenerate49.056, checkpoint0,
511 righe trattenute e stato capacità5.155.256 B. L'upper dell'evaluator
resta32 MiB: heap della fase byte nominato100.596.216→134.150.680 B.
Core di cella637.487.748 prodotti, fold45.512.396 prodotti,70.007
callback/replay di frame e named heap complessivo748.973.221 B invariati.
I contatori non costituiscono accounting completo o raffinamento Lean.

## Risorse e occupazioni non attribuite

| Prova | Wall s | Fisico stabile campionato B | Campioni | Incompleti |
|---|---:|---:|---:|---:|
| A1 | 166,481 | 723.087.360 | 832 | 1 |
| B1 | 156,879 | 743.817.216 | 784 | 0 |
| B2 | 157,278 | 743.993.344 | 786 | 0 |
| A2 | 165,471 | 1.279.930.368 | 823 | 0 |

Zero failure smaps e nessuno stop risorsa. A1/B1/B2 hanno GPU0 in tutti i
campioni. **A2 registra15 campioni nonzero**, dalle16:45:04,841 alle
16:45:07,865 UTC, massimo556.793.856 B. Il programma della fixture è CPU;
il monitor non conserva inventory contemporanea dei processi GPU e
non permette attribuzione. Non si deduce isolamento della coppia BA,
né si sottrae quell'occupazione dal conto fisico.

Build644,391 s, RSS campionato2.970.877.952 B, fisico3.247.915.008 B,
3.217 campioni completi. Anche la build rileva15 campioni GPU non attribuiti
fino a556.793.856 B, dalle16:30:06,284 alle16:30:09,280 UTC.
GPU verificata idle prima/dopo tutte le prove e prima dello stop.
Il binario conservato ha35.992.528 B e SHA256
`c3f92b239b6e103635bae27fa9f90f9857b0ce616c11756f9675464b8981c20a`;
ricette SHA256 `b0c69fdb2395a1014f877725b119948af038a48baaebcbb4b336551f87f35853`.

## Decisione e chiusura

La contrazione byte è positiva nella fixture; il costo delle celle/replay
rimane il prerequisito principale del runner canonico. Il conto pubblico
shared adaptive481.289.178.399.996 prodotti Fp3 non è un tempo misurato.
Non esiste ancora un consumer RMS CUDA completo con replay/fold/core e
accounting simultaneo validati: un kernel del solo core con righe CPU
aggiungerebbe trasferimenti senza chiudere il caller. Nessuna selezione
canonica, nuovo setup AES o tentativo di produrre certificati dai soli hash.
Si conserva e spegne anticipatamente secondo il piano; continua il lavoro
locale sulla fattorizzazione degli stessi polinomi e selettori originali.

[Record di chiusura](../../benchmarks/results/c71-certificates-rms-byte-close-2026-10-11-30867b9b.json),
SHA256 `f8160504d9b83ca392b42321fa87a3611c5c7200a9c3b54137b05a6aedf6730c`.
Stop richiesto16:46:59,827 UTC; i primi cinque poll segnalano EXITED ma
runtime ancora presente, perciò la conferma iniziale fallisce e il guard
resta vivo. Un tentativo anticipato di ritiro fallisce chiuso sulla
ricevuta assente, senza inviare segnali. Follow-up GET conferma
**EXITED/runtime assente16:48:04,629 UTC**; guard PID21664/start ticks332107132
ritirato solo dopo alle16:48:33,191 UTC. Avvio/deadline autorizzati non
sono spostati dallo stop anticipato.

Bundle privato `certificates-rms-byte03-20261011`:80 file,39.807.724 B,
manifest SHA256 `334bc335b65e69c2ab1840ed31052e0d9a6e51162f8ad9b6b7c11d74a52dd578`.
Bundle chiusura `certificates-rms-byte03-close-20261011`:17 file,24.574 B,
manifest `1f387c7ebaa3e995d706657b7628d1ac603c5e7ceb87c6187b82a03b87262fc3`.
Tutti gli hash verificati, manifest originali intatti, nessuna rimozione.
