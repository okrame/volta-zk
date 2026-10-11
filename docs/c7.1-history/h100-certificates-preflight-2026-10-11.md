# C7.1 — ingest, allocatore e RMS completo ridotto, 11 ottobre 2026

Il [record immutabile](../../benchmarks/results/c71-certificates-preflight-2026-10-11-c31f46b6.json)
conserva provenienza, manifest verificati, negativi operativi e misure della
[campagna corrente](h100-certificates-start-2026-10-11.md). Nessun certificato
canonico è stato generato o verificato. La deadline non cambia.

Gli shard pinned scaricati sono verificati integralmente. Il nuovo ingest
produce esattamente il packed originale, 61.394.690.560 B, SHA-256
`1a88da14c15d24133d0df40ff2a3acdbc54e7b91634a8304e787a5701ac8dac8`;
coincidono anche digest e mappa degli esponenti. Γ originale è riusato,
senza ricalibrazione. Il primo wrapper download fallisce per `/usr/bin/time`
assente, prima di iniziare il download; l’esito rimane conservato.

Il replay delle sole allocazioni da almeno 1 MiB del gruppo storico 31
completa 512 cicli in 227,686 s. Non contiene W, kernel o allocazioni piccole.
Il campione congiunto massimo è 5.771.866.112 B, sotto il cap fisico
6.174.015.488 B; non riproduce lo spike storico. Il monitor canonico restituisce
comunque exit 1 al controllo finale perché mancano census e completamento
canonici. Non trasformiamo questo esito in un pass. Il cleanup delle
allocazioni riesce e la GPU torna idle. La nuova modalità `component`
mantiene lo stesso cap fisico, senza esenzioni W o credito di protocollo.

La misura RMS usa cinque ricette originali, frame sintetici nonzero valutati
dal riferimento intero, correlazioni ideali da fixture e tutte le 99 profondità
originali del prover GKR. Entrambe le prove ridotte verificano endpoint MAC,
digest FS e consumo completo delle correlazioni:

| Celle vive / dominio | Prover | Verifier | Prodotti Fp3 dei coefficienti | Byte wire |
|---|---:|---:|---:|---:|
| 15 / 16 | 4,281989 s | 0,205585 s | 10.303.518 | 252.340 |
| 255 / 256 | 15,437596 s | 0,241374 s | 195.749.022 | 305.284 |

Il test a 256 celle ha RSS campionato 153.268.224 B. Il campionatore osserva
anche memoria GPU temporanea globale pur essendo il benchmark CPU; non viene
attribuita al GKR. La GPU risulta idle al controllo successivo. I campioni
non sono un picco completo. Il compilatore impiega circa 79 ms nei due casi.
Sono esclusi caller statistico, PCS, modello reale, setup AES e risposta
completa. Il mix di cinque ricette non rappresenta quantitativamente tutti
i 159 programmi: nessun tempo canonico è estrapolato. Il costo analitico
residuo di 844.006.203.160.300 prodotti Fp3 resta un impedimento sostanziale.

L’export già implementato aggiunge 32.768 B al ledger, che riusa ricevute
tipate originali e misura il marker corrente. Le 653 fasi danno massimo
nominato 5.878.767.874 B e 26.812.158 B residui condivisi. `joint_admitted`
e verifica fisica rimangono false. Il ledger comprende flag trattenuto,
owner e cache W vive nel setup AES; non estende alcun cap.

La nuova ipotesi sullo spike richiede kernel e W reali. La build
`C71_OWNER_TRACE_PHYSICAL` misura memoria CUDA ai confini owner e registra
variazioni di overhead da 16 MiB, oltre agli snapshot. Owner 42.136 B,
record 512 B, cap file 16 MiB. I quattro test del logger passano in 54,83 s,
i 44 test monitor in 4,83 s e i nove controlli documentali in 1,02 s.
Il primo launcher CUDA usa una directory errata e non avvia compilazione;
il secondo, con cwd esplicita, completa in 21,818 s. Entrambi sono conservati.
Questa build diagnostica non è selezionata per il runner definitivo.

Le premesse di raffinamento Rust/CUDA, Seed6 e allowance fisica rimangono
aperte. Nessun enunciato Lean o garanzia del protocollo cambia. La prossima
azione è attribuire lo spike nel componente A e selezionare un miglioramento
esatto del costo RMS prima di un nuovo setup completo.
