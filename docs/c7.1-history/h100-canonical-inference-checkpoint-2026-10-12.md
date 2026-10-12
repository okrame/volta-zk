# H100 — AES/inferenza O=0 completi, commitment A in corso

[Checkpoint immutabile](../../benchmarks/results/c71-certificates-inference-control-checkpoint-2026-10-12-16d60d38.json)
SHA25645db142fbfe4d931ca5bcd6336a718f8ac44c01a670fb4b0cd0a92ba153c4484;
43 file chiusi,5.293.985 B trasferiti con hash verificati, pesi/KV/pool esclusi.
Sorgente canonica pulita16d60d38, nessun restart/sessione importata.

I due ruoli terminano Seed6 reale/AES: prover1499,8176 s,
verifier1499,8194 s. Preparazione numerica O=0 inclusa inferenza completa
78,6538 s: non è il tempo inference-only o una prova accettata. Commitment
A a64/512 al checkpoint11:03 UTC,100/512 alle11:07 UTC; processo59788
con stesso starttick vivo, stderr vuoto. Zero risposte/certificati accettati.

Watcher VM solo controllo/streaming, nessun calcolo di protocollo locale:
conserva subito C71RSP01 completo e, quando disponibili, C71ACC01 e journal.
Accettazione richiede BLAKE3 body calcolato indipendentemente sul pod,
ack accepted1/context uguale, end response_total del prover dopo fsync/
promozione, stesso receipt nei prefissi accettati dei due journal. Non
importa stato o rinnova correlazioni. Piccolo parser ha self-check di
integrità; utility hash usa la BLAKE3 già compilata, fixtureabc non è un
certificato. Primo linker fallito per thread/AS2GiB conservato, risolto
con un core/linker thread; processo canonico invariato. Nove documentali
passano nel worktree isolato927a181f senza cambiare il run16d60d38.

Premesse crittografiche/NoPeek e raffinamento runtime restano quelle del
design; il watcher controlla evidenza del verificatore originale, non lo
sostituisce. Guard provider indipendente e sei ore originali invariati:
compute end13:19:04, hard stop13:49:04 UTC. Segue prova completa O=0,
poi O=150/300 solo dopo accettazione precedente nella stessa sessione.
