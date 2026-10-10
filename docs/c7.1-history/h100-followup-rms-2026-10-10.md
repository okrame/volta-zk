# C7.1 — screen RMS coarser sulla H100, 10 ottobre 2026

[Record](../../benchmarks/results/c71-h100-followup-rms-2026-10-10-0ef9db4fe6f1.json),
checkout pulito `0ef9db4f`, runner `cfc04b6f`, libreria pool+fill verificata.
Il [criterio precedente al trial](h100-comparison-plan-2026-10-10.md)
richiede tutte le 50 decisioni O=0 identiche al riferimento, oltre ai
controlli numerici. Cambiano solo gli input/output RMS dispari al pari
coarser; W, esponenti W, embedding/Pi, workload e geometria A restano fissi.
Candidata `a3e5b03a1af642ab3567bd019890254525b194dea154b4cc1d85a78db03cd286`.
Le tabelle rigenerate e validate sono byte-identiche a quelle originali.

Il trial termina exit 0 senza stop risorsa o errore numerico terminale:
326,339 s totali, **77,210 s inferenza O=0**, 100 token di prompt e 50
generati, ultimo token consumato in KV. Il prompt coincide; **2/50 token
generati coincidono, prima differenza alla terza decisione**. Cleanup
completo, alloc/free bilanciati, W e arena ritirati. Lo screen è respinto:
non si avviano O=150/300 né la linea di sostituzione. La prima decisione
diversa modifica gli input successivi e KV; 2/50 non equivale a 48 errori
indipendenti o a un punteggio generale di qualità. Non è stato verificato
indipendentemente il requisito di non degenerazione; un esito senza errore
non lo dimostra. Γ originale resta l'unico ammesso.

Il compilatore originale su tutte le ricette dei tre contesti conferma
159→91 programmi, identici ai metadati congelati di ciascuna candidata.
Possesso cumulato dei soli programmi 457.634.736→260.594.224 B, massimo
singolo 2.928.784→2.904.208 B; CLI e serializzazione 2,804→1,613 s,
un thread, AS CPU 2 GiB più stretto del cap pod, durante setup AES del
trial canonico. Sono componenti, senza picco simultaneo di compilazione,
tempo dei caller RMS, replay/GKR/PCS o risparmio della risposta completa.
Il −13,9216% dei prodotti Fp3 e −43,0563% dei byte dei circuiti restano
screen analitici; callback, depth e 512 replay A sono invariati.
Il nuovo ledger resta `calibrated:false` e senza ammissione congiunta.

Monitor canonico, CPU wrapper AS 64 GiB e solo figlio CUDA senza AS,
cap e margini invariati. Massimo temporaneo stabile campionato
1.219.804.672 B, payload osservato 692.818.293 B: sola inferenza O=0,
nessun picco fisico istantaneo o canonico completo. Nessun commitment,
setup crittografico, prova, verifica o certificato. Nuove scale non
ereditano errore quantitativo, due replay esatti, confronto indipendente
e ammissione del Γ originale.

Bundle `h100-followup-rms-20261010T212015Z`: 14 file, 372.046 B,
manifest `d097e5975fa6b9a732dbfcb94e5758557678d112d01a53feb2b5f4008f657a8f`.
Compiler e criterio pretrial nel bundle
`h100-followup-default-20261010T192300Z`, manifest
`05d77bfa2388f210e28bd6ff01a06b58a41ec4869ca3a76dc1c4f627ee1a4210`;
nuovo ledger in `h100-followup-profile-20261010T195900Z`. I manifest
precedenti restano intatti, nessuna calibrazione del riferimento.
