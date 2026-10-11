# RMS batching — calendario analitico eseguito

Checkout pulito `b13ccaa24574752ad2f304aea2b5973e972891a3`, worktree separato
CPU sullo stesso pod. Dieci test del calendario e nove documentali passano;
quattro screen prefix/cell a cap256/4096 completano sotto un secondo.
Il [record](../../benchmarks/results/c71-certificates-rms-batched-schedule-2026-10-11-b13ccaa2.json)
ha SHA-256 `87535cc926bd3b628b4f963ce9d66f0cd958b0e328f4e2f98d39a9c5f8eda5b9`;
59 raw, archivio256.087 B, manifest/hash verificati. GPU zero nei campioni,
nessun incompleto. Nessun calcolo del calendario sulla VM.

Il prefisso ricostruisce7.326 launch dell'oracolo denso e707.364 del159/99
effettivamente conservati su `f868468e`. La candidata tail predice280.299
prima del completamento del suo trial; il record conserva esplicitamente
`cell_not_yet_compared_with_gpu:true`. Il [successivo risultato tail](h100-rms-tail-program-reduction-parity-2026-10-11.md)
osserva280.299: servono controlli nuovi/record collegato, senza riscrivere
lo screen predittivo. Due nuovi test preparati confrontano quel record
GPU sia sul denso16.384 sia sulle159 ricette/99 profondità.

| Calendario analitico | Cap256 | Cap4096 |
|---|---:|---:|
| Prefisso batched, tail precedente | 182.431.475.427 | 11.405.418.264 |
| Prefisso batched e tail per programma | 3.307.175.412 | 209.567.637 |

I conti includono cella e indici e mantengono tutte le
1.328.755.507.200 posizioni padded del tail. La riduzione delle launch
non riduce queste riletture. Sono esplicitate anche le CTA per programma,
i valori/range privati e i piani host/device richiesti; non sono il conto
simultaneo completo. Tutti gli screen sono `credit:false`,
`complete_work:false`, `joint_admitted:false`. Nessun tempo, capacità
completa o target65 s ammesso. Byte/statistica GPU, raffinamento,
modello/real-AES/certificato e journal rimangono aperti.
