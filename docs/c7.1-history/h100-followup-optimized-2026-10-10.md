# C7.1 — confronto SDPA sulla H100, 10 ottobre 2026

[Record](../../benchmarks/results/c71-h100-followup-optimized-2026-10-10-0ef9db4fe6f1.json),
checkout pulito `0ef9db4f`, stesso pod H100 autorizzato. Metodo fissato nel
[piano](h100-comparison-plan-2026-10-10.md), con la
[correzione degli scalari pubblici](h100-sdpa-scalar-correction-2026-10-10.md).
Il primo caricamento fallito resta conservato; nessun risultato ne deriva.

Entrambe le precisioni completano warmup O=0 e due passate fresche a
O=0/150/300: teacher forcing sui token ammessi e generazione libera.
Ogni risposta usa 100 token di prompt, 50 decisioni greedy e consumo
dell'ultimo token in KV, 51 forward; contesti finali 150/300/450.
PyTorch 2.8.0+cu128, Transformers 5.19.0, SDPA automatico, batch 1,
TF32 disattivato, riduzione BF16 abilitata. Il kernel SDPA effettivo
non è identificato da una timeline.

| Precisione | Load, s | Warmup O=0, s | Teacher forcing O=0/150/300, s | Libera O=0/150/300, s |
|---|---:|---:|---|---|
| BF16 originale | 168,845 | 2,742 | 2,449 / 2,473 / 2,439 | 2,444 / 2,634 / 2,420 |
| i16 dequantizzata in BF16 | 265,833 | 2,815 | 2,523 / 2,546 / 2,493 | 2,523 / 2,687 / 2,525 |

Questi sono wall della risposta, inclusa preparazione input/maschere;
i forward sincronizzati comprendono controllo finiti e selezione greedy.
Prefill e decode sono separati nel record; load e warmup non confluiscono
nei tempi delle passate. Una sola esecuzione per precisione in ordine
fisso, senza intervalli di confidenza. Il caricamento non misura kernel
d'inferenza.

I 357 raw head prima del softcap sono finiti e BF16 in ciascun trial.
Teacher forcing concorda con 45/49/50 decisioni su 50 per BF16 originale
e 44/49/50 per i16→BF16. In libera, entrambi concordano con 2/50 decisioni
per risposta; dopo una divergenza cambia anche la storia KV. Norm,
accumuli e softmax floating e l'ulteriore arrotondamento BF16 dei pesi
dequantizzati non implementano la relazione intera GemmaQuantV1.
I 76,760 s del caller intero con pool a O=0 sono un termine di confronto
sullo stesso prompt e lunghezza, senza equivalenza numerica o accelerazione
della prova. SDPA rimane diagnostico: non selezionato nel protocollo.

Entrambi terminano exit 0 senza stop risorsa. Picchi PyTorch
allocated/reserved 64.223.782.912 / 64.508.395.520 B; massimo GPU intera
campionato 65.156.415.488 B. Il monitor usa il modo `calibration`, con
limiti host/GPU globali, deadline e margini; non applica o dimostra il
cap temporaneo canonico. CPU wrapper AS 64 GiB, solo figlio CUDA senza
AS. Nessun picco fisico istantaneo, canonico, prova, ammissione Γ o
raffinamento formale deriva da questi campioni.

Bundle `h100-followup-optimized-20261010T211429Z`: 30 file, 438.214 B,
manifest `15c2486fc857f935ccb01522c55204958bf634433925225f886c1ca998c50ddb`.
Comprende il controllo esatto dei 60 scalari e il fallimento del probe
CPU che tentava di mappare lo shard da 49,8 GB sotto AS 64 GiB; il probe
corretto legge solo i metadati e due byte per scalare. I manifest
precedenti restano intatti. Γ originale resta l'unico ammesso e i
certificati canonici verificati rimangono zero.
