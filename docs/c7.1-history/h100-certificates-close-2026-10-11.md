# C7.1 — chiusura campagna certificati, 11 ottobre 2026

**Obiettivo minimo non raggiunto: zero certificati canonici generati e
verificati**, nessuna accettazione durevole, nessun contesto O=0/150/300
completato. Non esistono quindi percorsi, dimensioni o hash di certificati
canonici da consegnare. La sequenza nella stessa sessione non è eseguita.
Il [record di chiusura](../../benchmarks/results/c71-certificates-close-2026-10-11-0d200623.json)
conserva questa distinzione e le conferme provider.

Il solo pod autorizzato `z6wx2kkn69eoc0`, H100 80 GB, è spento. Avvio
conservativo 07:31:18.237529 UTC; richiesta stop 12:58:51.448317 UTC,
prima conferma `EXITED` 12:59:00.251405 UTC, conferma con `runtime:null`
**12:59:46.550898 UTC** (14:59:46 Italia). Durata conservativa
19.708,313369 s, **5 h 28 min 28 s**, entro otto ore comprese conservazione
e chiusura. Fine calcolo originaria 15:01:18 UTC, guard 15:26:18 e hard
stop 15:31:18; nessuna deadline spostata. Il guard è ritirato con pidfd e
identità PID/start ticks verificata solo dopo conferma di spegnimento.

## Risultati effettivi

- [Primo commitment A completo del modello](h100-certificates-a-vmm-pool-2026-10-11.md):
  VMM differito e pool limitato alla fase iniziale, 512/512 gruppi O=0,
  commitment 3.408,762 s, processo 4.158,144 s. Massimo fisico campionato
  5.861.006.848 B su cap 6.174.015.488 B; payload osservato 5.435.740.354 B
  su 5.905.580.032 B. Allocazioni/rilasci bilanciati, zero arena/W dopo
  cleanup, GPU idle. Esclusi W PCS, setup AES, proof body e verifica.
- [RMS completo della fixture su 159 ricette](h100-certificates-rms-all-recipes-2026-10-11.md):
  99 profondità, 511 celle vive sintetiche più padding; prover baseline/
  candidata 194,166/191,238 s, verifier 6,577/6,602 s. Due verifiche
  originali FS/MAC riuscite, 320.320 B di wire ciascuna, correlazioni ideali.
  Una sola coppia con occupazione GPU non attribuita in 15 campioni della
  candidata: −1,51% osservato, nessun guadagno stabile o tempo canonico.
- Esportazione immediata dei certificati implementata in `5dfdcfce`, con
  byte, hash, pubblicazione senza sovrascrittura e ricevuta dopo journal
  del verifier. Verificata su fixture di trasporto; mai esercitata da un
  certificato reale completo in questa campagna.

I negativi fisici e di tracing restano conservati: A a 41, 15 e 82 gruppi,
logger esaurito e VMM senza pool interrotto per ritmo insufficiente.
Il completamento combinato non attribuisce retroattivamente una causa
unica agli spike. La deviazione AS CPU 128 GiB di `a-async04` resta nel suo
[record](../../benchmarks/results/c71-certificates-a-async04-2026-10-11-a525ecf8.json);
il monitor successivo impone AS 64 GiB autonomamente. Il primo census
locale RMS privo di wrapper resta distinto dal successivo controllo
bounded nel [checkpoint](h100-certificates-rms-endpoint-2026-10-11.md).

## Mancanza che impedisce il certificato

Il core RMS corrente resta **751.359.028.655.932 prodotti Fp3 CPU** per
risposta e **998.927.195.904 callback** del checkpoint. Sono conti analitici;
la misura ridotta non è extrapolata in un tempo completo. La riscrittura
esatta toglie il 10,98% dei prodotti del core precedente, ma non risolve
questo percorso. Perciò non è stato avviato un nuovo setup AES né un nuovo
runner canonico completo: un altro prefisso non avrebbe soddisfatto la
richiesta. La campagna viene chiusa anticipatamente con l’obiettivo aperto.

VMM + pool resta diagnostico. Il suo ledger generale O=300 supera ancora
il payload di 29.066.098 B; il positivo A O=0 non misura tutte le fasi del
runner, i picchi istantanei o l’allowance complessiva. Nessun credito del
target 65 s, nessun certificato ottenuto sostituendo endpoint, Γ o PCG.
Il prossimo passo necessario è una riduzione sostanziale esatta del
lavoro/implementazione RMS, con parità wire/FS/MAC e conto completo, prima
di una nuova sessione canonica da O=0. Journal, KV, monete e correlazioni
terminali non sono riutilizzabili.

## Stato scientifico e conservazione

Γ originale resta ammesso dopo le verifiche d’identità, senza ricalibrazione.
Modello, workload, KV finale, semantica intera, PCS, NoPeek, MAC e trust
model sono invariati. Restano aperte composizione malevola e risorse della
riduzione Seed6, raffinamento Rust/CUDA/Fp3/VMM, determinismo del replay,
provenienza dei prefissi e verifica positiva del runner completo. Le
identità algebriche e i test finiti non sono nuovi lemmi di raffinamento.

Il bundle finale `artifact/c7.1-pod/certificates-close-20261011T130000Z`
aggiunge 38 file / 79.802.043 B, inclusi input Γ e librerie, dopo verifica
di 837 entry dei manifest precedenti. Riferisce 817 copie verificate già
conservate senza duplicarle; nessun file di evidenza precedente è rimosso.
Manifest SHA-256:
`9f790287d13f74eca79df216d9cdf99ea1082b00fd46065c77d3efb04fe81189`.
Pesi/shard e checkout ricostruibili sono esclusi; identità e input Γ restano.

Le ricevute provider, deadline, ritiro guard e controlli locali sono in
`artifact/c7.1-pod/certificates-close-receipts-20261011T130100Z`;
manifest SHA-256
`4ddf2c4333facdc3a6ae31a73a299d1a9b9f81dbb99e7d45ac22b2cbbe8f1d8a`.
Il totale privato resta sotto 10 GB. I singoli manifest A/RMS sono nei
record collegati. I cinque documenti attivi sono aggiornati insieme,
con controlli documentali; nessuna nuova build per la chiusura.
Il branch dedicato è `runpod/z6wx2kkn69eoc0/c71-certificates-20261011`,
pubblicato via Git HTTPS senza force-push o merge.
