# C7.1 — chiusura del seguito H100, 10 ottobre 2026

La [campagna autorizzata](h100-followup-start-2026-10-10.md) sul solo pod
`z6wx2kkn69eoc0` è chiusa. Il provider conferma **EXITED e runtime assente
alle 21:24:47,289 UTC**, cioè 23:24:47 Italia del 10 ottobre. Avvio
conservativo 16:27:24,201 UTC, durata fino alla conferma 4 h 57 min 23 s;
stop 1 h 2 min 37 s prima della deadline 22:27:24,201 UTC. Nessun nuovo
hardware o estensione. Guard indipendente PID 4077733 ritirato soltanto
dopo la conferma provider, identità/start ticks verificati e uscita
confermata tramite pidfd. Prima dello stop, nessun processo CUDA nativo
o profiler attivo sul pod.

[Record di chiusura](../../benchmarks/results/c71-h100-followup-close-2026-10-10-9803f4a123d2.json),
checkout locale pulito `9803f4a1` alla conservazione finale. Base
`ccbea66b`, lavoro del proprietario preservato. Branch dedicato
`runpod/z6wx2kkn69eoc0/c71-h100-20261010`, pubblicazione Git HTTPS senza
force push o integrazione di branch. Il checkout anonimo separato sul
pod verifica SHA e 14 digest di documenti/evidenze prima dello stop;
la chiusura con stato provider è pubblicata e verificata successivamente
da un checkout HTTPS separato sulla VM. Il primo aggiornamento del
checkout shallow di verifica fallisce exit 128; selezione diretta della
SHA già scaricata corregge il controllo, senza nuovo lavoro numerico.
Fallimento operativo e ricevute sono conservati.

## Risposte alle domande hardware

**Spike A.** Il [default canonico senza profiler](h100-followup-default-2026-10-10.md)
completa W/setup e 116/512 gruppi, poi supera il cap fisico:
6.545.690.112 B contro 6.174.015.488 B. Step GPU 511 MiB, RSS costante,
massimo native osservato invariato. Il [componente A senza PCS W/setup AES](h100-followup-callers-2026-10-10.md)
si ferma dopo 33 gruppi a 6.494.850.560 B, step 496 MiB con RSS costante.
La presenza di quello stato canonico non è necessaria al negativo del
componente; W host/device resta residente. Non è identificata
l'allocazione, il kernel o una cache/leak responsabile. I
[due tentativi Nsight](h100-profiler-limit-2026-10-10.md), incluso il
componente con memory graph disattivato, superano il cap prima del
primo gruppo: nessuna timeline utilizzabile dello spike. La traccia
owner completa satura 16 MiB nel primo gruppo; quella large-only
conserva un [prefisso](h100-followup-spike-prefix-2026-10-10.md), senza
copertura esterna degli eventi omessi. Non si alzano cap o allowance.

**Pool.** Le [tre inferenze reali](h100-followup-inference-2026-10-10.md)
completano gli stessi 150 token ammessi: 85,144 s senza pool, 76,760 s
solo pool, 77,050 s pool+fill. Il −9,847% è una coppia osservata, con
1.185.769 allocazioni evitate e lanci, fence e traffico identici;
256 B device e 8 B owner aggiunti restano conteggiati. Pool selezionato.
I sei confronti A alternati completano 36/16/5/33/22/15 gruppi; sui
gruppi 1–4 comuni, pool −0,148% osservato è inferiore alla variazione
fra ripetizioni. Confermati 13.667 alloc/free evitati per gruppo;
nessun vantaggio A stabile o root A completo dimostrato.

**Fill.** I medesimi sei confronti A confermano 3.840 lanci applicativi
in meno per gruppo, con identiche copie, 55.069 fence e visite delle
fonti. Il −0,323% osservato è inferiore alla variazione fra ripetizioni.
Fill mantenuto come semplificazione esatta, senza guadagno wall stabile
o risparmio del lavoro fisico di azzeramento. Le tre librerie passano
[parità CUDA finita](../../benchmarks/results/c71-h100-followup-preflight-2026-10-10-7b0885ad316f.json)
prima dei confronti. Lo startup pooled respinto durante il precedente
teardown è conservato; GPU idle verificata prima dei nuovi caller,
senza esenzione W o cap aumentati.

**Motore ottimizzato.** [Entrambe le precisioni SDPA](h100-followup-optimized-2026-10-10.md)
completano warmup e due passate fresche O=0/150/300, 100+50 token e KV
finale 150/300/450. Wall risposta BF16 originale 2,420–2,634 s e
i16→BF16 2,493–2,687 s; load 168,845/265,833 s separato. Tutti i 357
raw head prima del softcap sono finiti per precisione. Teacher forcing
concorda con 45/49/50 e 44/49/50 decisioni su 50; libera con 2/50 per
risposta. Floating, arrotondamento BF16 e storie divergenti non
implementano la relazione intera. SDPA resta diagnostico, senza credito
di protocollo, confronto con il motore più veloce possibile o picco
fisico canonico. Il loader inizialmente imponeva erroneamente scalari
unitari: [corretto contro i 60 bit BF16 pubblici](h100-sdpa-scalar-correction-2026-10-10.md),
fallimento originale conservato, riferimento intero e Γ non modificati.

**RMS coarser.** Lo [screen numerico](h100-followup-rms-2026-10-10.md)
termina senza errore e con cleanup completo: 77,210 s inferenza O=0,
2/50 token generati coincidenti e prima differenza alla terza decisione.
Respinto dal criterio fissato prima del trial, linea di sostituzione
fermata, O=150/300 non avviati. Non è una misura generale di qualità o
48 errori indipendenti. Il compilatore originale conferma 159→91
programmi, 457.634.736→260.594.224 B posseduti e CLI 2,804→1,613 s;
sono componenti, senza tempo dei caller RMS/GKR/PCS o picco composto.
Ledger coarser `calibrated:false`, nessuna nuova ammissione.

## Stato canonico, controlli e blocchi

**Zero certificati canonici. Γ originale resta l'unico ammesso.** I suoi
otto file selezionati, compreso il manifest di trasferimento, sono
ricontrollati alla chiusura; W/shard/packed nuovi avevano passato tutti
gli hash originali prima del riuso. Nessuna calibrazione del riferimento.
Journal, KV e correlazioni terminali non sono ripresi. PCS sui valori
VOLE originali, NoPeek, geometria 512, PCG AES reale e fail-closed
restano quelli selezionati. Il negativo fisico irrisolto impedisce il
seguito canonico; non si ripete un trial fallito senza nuova ipotesi.

Controlli pertinenti: 48 filtri CUDA reali sulle tre librerie, ulteriori
parità della build trace, 43 test del monitor con subreaper/daemon e
PID reuse, due test dello schedule SDPA, nove controlli documentali.
Il probe reale di cleanup Nsight corregge una prima ricevuta che
controllava solo il target e non l'agent orfano; entrambi gli esiti sono
preservati. Timeout di build, limiti trace, stop fisici, startup NVML,
timeout della query NVML al confine della fase e loader fallito restano
evidenze negative, senza credito da una fase incompleta.

Restano aperti attribuzione dello spike e sufficienza dell'allowance,
root A/512 gruppi e picco congiunto completo, prova/verifica dei tre
contesti e target 65 s. Il conto analitico conserva
844.006.203.160.300 prodotti Fp3 CPU e 998.927.195.904 callback per
risposta; compiler e screen non misurano questo lavoro completo.
Le premesse Seed6/composizione e raffinamento Rust/CUDA dichiarate nel
[design](../c7.1/design.md) e nella [sicurezza](../c7.1/security.md)
non sono scaricate da parità finite o misure di componente.

## Conservazione

Dieci bundle numerici/preflight: **1.194 file verificati SHA-256** prima
dello stop. Bundle finale `h100-followup-close-20261010T212601Z`:
20 file, 23.854 B, manifest
`92bd1daab631493fc791048c158c7c12e585f088c5ee8036395a1e08f319ef1f`.
Contiene query provider, deadline, guard/ritiro, verifiche di Γ,
pubblicazione e inventario; nessuna credenziale o chiave. Totale privato
**303.879.152 B**, cap 10.000.000.000 B, nessuna rimozione. Tutti i
manifest originali e gli input Γ necessari restano intatti. Verificati
anche 3.095 record e file storici preesistenti rispetto a `ccbea66b`,
escluso il solo indice di navigazione aggiornato. Il record di chiusura
lega i nove nuovi record numerici tramite digest; ogni failure conserva
provenienza e cap originali.
