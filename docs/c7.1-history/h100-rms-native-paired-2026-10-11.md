# RMS tail — confronto AB/BA sullo stesso H100

Quattro processi indipendenti, ordine A1/B1/B2/A2, nessuna build o altro
lavoro computazionale concorrente. A usa il CUDA prefisso batched pulito
`f868468e`, B il CUDA tail per programma pulito `c0e0448d`; entrambi usano
lo stesso harness Rust congelato. Hash dei due binari controllati prima
di ciascun lancio, ricette originali fissate, GPU idle a tutti i bordi.

Il [record](../../benchmarks/results/c71-certificates-rms-native-paired-2026-10-11-c0e0448d.json)
ha SHA-256 `7e04685b9288d2922eb6f7d7704aa0cc84196e5d5a40add01940ec78aed9d060`;
57 raw, archivio287.424 B, manifest/hash verificati in streaming.
Medie calcolate sul pod:127,079→113,956 s, riduzione osservata10,3266%.

| Trial | CUDA | Prover s | Campioni incompleti |
|---|---|---:|---:|
| A1 | f868468e | 126,664 | 0 |
| B1 | c0e0448d | 114,221 | 0 |
| B2 | c0e0448d | 113,691 | 1 |
| A2 | f868468e | 127,494 | 0 |

Tutte le159 ricette/99 profondità su511 celle nonzero sintetiche/512
padded, GKR/FS/MAC originale e byte CPU contracted32 MiB. Wire320.320 B,
BLAKE3 e9.919 correlazioni ideali uguali tra le quattro prove e tutti i
quattro riferimenti CPU congelati. Owner42.496 B dopo cleanup, arena0,
1.288 allocazioni/rilasci, nessuno stop/cleanup incerto. Launch707.364
in A e280.299 in B. Le righe ideali deterministiche sono test, senza
pretesa di riuso monouso in una sessione reale/AES.

Fisico campionato A1/A2:1.269.985.280/1.270.317.056 B, senza incompleti;
B1:1.269.207.040 B, senza incompleti. B2:1.273.843.712 B, un incompleto,
nessun credito al suo picco stabile. GPU460.324.864 B osservata in
A1/B2/A2,458.227.712 B in B1; nessun picco istantaneo completo o credito
di isolamento fisico canonico. Limiti fisici, arena e deadline invariati.

Sono escluse statistica, modello, PCS, real/AES, risposta/journal e conto
simultaneo canonici. Zero certificati, nessuna extrapolazione del target
65 s. Il confronto misura il miglioramento di questo componente ridotto.
La fixture ragged è compilata soltanto dopo il termine AB/BA23:14:47 UTC.
VM solo editing/controllo/verifica streaming; campagna originale invariata.
