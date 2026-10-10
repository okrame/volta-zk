# C7.1 — metodo dei confronti H100, 10 ottobre 2026

La nuova campagna autorizzata conserva Γ ammesso e W verificata. Questo
documento fissa il metodo prima dei risultati; non concede credito.
Il [seguito locale](local-followup-2026-10-10.md) resta la base scientifica.

## Inferenza ottimizzata

Il confronto usa Transformers 5.19.0, PyTorch 2.8.0+cu128 e SDPA sul
checkpoint/config pinned. Nessun tokenizer nuovo: prompt di 100 ID dal
workload originale. BF16 dei corpi originali e W i16 dequantizzata in BF16
sono trial distinti. Norm/softmax/accumuli floating non sono GemmaQuantV1;
nessuna equivalenza intera o ammissione deriva dal confronto.

`scripts/c71_optimized_inference.py` carica soltanto i parametri text,
verifica tutte le forme, il layout packed e le identità Γ/W della storia.
Ricarica gli scalar unitari e ricrea i buffer pubblici embedding/RoPE,
inclusi quelli non persistenti; meta/to_empty non fornisce tali valori.
LM head ed embedding rimangono condivisi. Errori, non-finiti o CUDA
indisponibile terminano il trial senza backend sostitutivo.

W load e un warmup O=0 sono separati. Due passate fresche mantengono KV
continuo a O=0/150/300: teacher forcing sui 450 token ammessi, poi
generazione libera. Ogni risposta ha lo stesso prompt, 50 selezioni greedy,
ID minimo nei pareggi, nessuno stop EOS e consumo dell'ultimo token in KV.
Il prefill calcola anche tutti i logits del prompt, come il lavoro della
head del runner intero. Cinquantuno forward coprono 100+50 token.
Prefill/decode sono sincronizzati e includono controlli/argmax; il wall
totale include anche preparazione degli input e maschere. Registrare
capacità CUDA allocated/reserved e monitor host/device/cgroup, senza
esenzioni o ammissioni della prova. Il backend dichiarato è SDPA automatico;
un confronto senza timeline non identifica il kernel SDPA effettivo.

## Candidata RMS coarser

La candidata iniziale è `rms-even-coarser` congelata nello screen locale:
solo input/output RMS al pari coarser, embedding e Pi fissi, W/esponenti W
immutati. Nuove ricette/tabelle devono essere generate e validate, senza
ricalibrare il riferimento. I domini A, i byte del workload e i 512 replay
non cambiano.

Screen conservativo fissato prima del trial: nessun overflow/non-finito,
nessuna degenerazione dei valori e **tutte le 50 decisioni O=0 identiche**
al riferimento ammesso. Una decisione differente respinge questo screen
di stabilità: si conserva il negativo e si ferma la linea di sostituzione.
Non prova che il modello sia inutilizzabile in altri contesti. Un successo
O=0 lascia ancora richiesti O=150/300, confronto indipendente completo,
errori quantitativi sui nuovi upstream, copertura e ledger completo;
non sostituisce Γ ammesso in questa campagna.

I costi compiler/plan/replay/GKR/PCS restano separati. I conteggi locali
−13,9216% core Fp3 e −43,0563% circuit bytes sono screen analitici; la
qualità e i tempi completi dei caller reali richiedono nuove misure.
