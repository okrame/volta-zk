# C7.1 — confronti reali dell’inferenza O=0

[Record](../../benchmarks/results/c71-h100-followup-inference-2026-10-10-b2468f3e1b17.json),
checkout pulito `b2468f3e`, runner `cfc04b6f`, librerie originali
`072de372` (senza pool), `8421fada` (solo pool), `b7c6d0ac` (pool+fill).
Stessi W/Γ/workload verificati, nessun profiler, sessioni e journal nuovi.
I tre caller terminano exit 0 senza stop di risorsa; i 150 token sono
identici alla storia ammessa. Nessuna calibrazione del riferimento.

| Variante | Inferenza, s | Allocazioni prima del close | Lanci | Fence |
|---|---:|---:|---:|---:|
| Senza pool | 85,143982 | 3.641.220 | 1.185.820 | 3.668.557 |
| Solo pool | 76,759851 | 2.455.451 | 1.185.820 | 3.668.557 |
| Pool+fill | 77,049992 | 2.455.451 | 1.185.820 | 3.668.557 |

Il pool elimina 1.185.769 allocazioni e 1.185.770 release osservate prima
del close; la differenza di una release è il flag ancora trattenuto.
256 B device e 8 B owner host sono contati. Il massimo native di capacità
è identico, 593.899.520 B. Copie D2D/H2D/D2H, lanci, fence e byte azzerati
coincidono; pool e pool+fill hanno tutti i contatori native identici.

In questa coppia il pool riduce il wall inferenza del 9,847%. È una sola
esecuzione per variante, in ordine fisso, senza intervallo di confidenza.
Il fill pubblico riguarda A: la differenza di wall fra le ultime due
inferenze non viene attribuita a esso. Seguono sei caller A di durata
bounded in ordine invertito per isolare pool e fill sul replay reale.

Il wall misurato include loop causale, copie e sincronizzazioni; W load
è separato. Conto fisico campionato di sola inferenza, senza prova/PCS W/A
o setup: non soddisfa il requisito di picco congiunto completo. Zero
certificati; Γ ammesso invariato. Il target della risposta 65 s resta aperto.

Bundle `h100-followup-inference-20261010T201900Z`: 36 file, 1.091.003 B,
manifest `f128fdfd5999871f9dea68ba6deff8e30b01dd0ccf004a4a12a342d6db5cb032`.
Manifest precedenti intatti; totale privato conservato 299.159.649 B.
