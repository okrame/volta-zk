# C7.1 — pool e fill sui caller A reali

[Record](../../benchmarks/results/c71-h100-followup-callers-2026-10-10-b2468f3e1b17.json),
checkout pulito `b2468f3e`, runner `cfc04b6f`, tre librerie del
[confronto d’inferenza](h100-followup-inference-2026-10-10.md).
Stessi W/Γ/workload, input nonzero, geometria A originale 512 gruppi,
nessun profiler. Il componente omette PCS W e setup AES canonici.

Sei run validi in ordine senza pool / solo pool / pool+fill, poi ordine
inverso. Ogni fase è bounded a 400 s, incluso caricamento e inferenza;
gruppi completi 36/16/5/33/22/15. L’avvio `pooled-01` è invece fermato
prima del lavoro numerico: NVML vede ancora 67.071.115.264 B del teardown
precedente, senza una nuova esenzione W. Fallimento conservato; nuove
etichette e verifica bounded di GPU idle correggono l’orchestrazione.
Le attese di rilascio sono registrate separatamente e non cambiano cap.

Il confronto usa i gruppi 1–4, comuni a tutti i run, escludendo gruppo 0
di avvio. La selezione è l’intersezione dei primi cinque gruppi successivi
all’avvio, senza scegliere in base al risultato del tempo.

| Variante | Mediane dei due run sui gruppi comuni, s | Mediana delle due, s |
|---|---:|---:|
| Senza pool | 5,881584 / 5,833744 | 5,857664 |
| Solo pool | 5,867065 / 5,830909 | 5,848987 |
| Pool+fill | 5,864701 / 5,795531 | 5,830116 |

Pool −0,148% e fill −0,323% osservati sono inferiori alla variazione fra
ripetizioni; non dimostrano un guadagno temporale stabile su A. Sono
confermati esattamente 13.667 alloc/free in meno per gruppo con pool e
3.840 lanci applicativi in meno con fill. Visite delle fonti, copie
H2D/D2H/D2D e 55.069 fence per gruppo coincidono in tutti i gruppi
confrontati. Il memset pubblico aggiunge 245.852.160 B al contatore degli
azzeramenti: prima le scritture del kernel zero non erano in quel contatore.
Nessun risparmio del lavoro fisico delle scritture deriva dal census.

Il pool resta selezionato per il [−9,847% osservato sull’inferenza](h100-followup-inference-2026-10-10.md)
con token esatti e contatori necessari immutati. Il fill resta una
semplificazione esatta con meno lanci, senza rivendicare un vantaggio
wall stabile. Nessuna estrapolazione a 512 gruppi o alla prova completa.

`current-02` termina per cap fisico a 33 gruppi: 6.494.850.560 B contro
6.174.015.488 B; payload osservato 5.554.384.779 B. Ultimi campioni GPU
crescono 496 MiB, RSS host costante, massimo native osservato invariato.
Lo spike non richiede la presenza del commitment W e setup AES in questo
componente; W host/device resta residente. Mancano timeline e attribuzione
a uno specifico kernel/allocazione/cache/leak. Non è una misura del picco
canonico. Cinque altri run terminano al budget di fase; `current-01`
conserva il timeout NVML al confine 400 s. Zero A/root/prove completi e
certificati; parità del root A completo non verificata.

Bundle `h100-followup-callers-20261010T210000Z`: 89 file, 3.719.610 B,
manifest `6dcbea297382880d146621470788764a4107adf688e4d075b6cf3e6ef3643f8f`.
Include i negativi e ricevute idle. Totale privato 302.896.976 B;
manifest precedenti intatti.
