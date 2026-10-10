# C7.1 — limite fisico della cattura Nsight

Il [trial canonico](../../benchmarks/results/c71-h100-followup-profile-2026-10-10-76a9201d8704.json)
usa checkout pulito `76a9201d`, runner `cfc04b6f`, libreria large-only
`b9043c5d`, arming 114 e cattura dopo 113 fino a 117 gruppi. W e Γ ammesso
verificati, sessione AES nuova. Completi installazione 212,665 s, setup
1.503,130 s e preparazione O=0 80,330 s; wall totale 2.036,946 s.
Al primo gruppo A il cap fisico ferma il runner: 6.715.858.432 B contro
6.174.015.488 B. Nessun gruppo completo, trace owner vuoto, nessun `start`
Nsight. Otto identità discendenti contate; GPU e agenti assenti alla
verifica successiva. Zero certificati, nessuna timeline dello spike.

La [nuova ipotesi](h100-component-window-plan-2026-10-10.md) elimina il
grafico allocazioni CUDA e lo stato canonico W/setup dal caller A.
Il [trial di componente](../../benchmarks/results/c71-h100-followup-component-profile-2026-10-10-b2468f3e1b17.json),
checkout pulito `b2468f3e`, conserva runner/libreria, geometria 512 e cap.
Preparazione 76,876 s, wall 169,795 s. Anche qui stop al primo gruppo:
6.574.624.256 B, zero gruppi completi, finestra 1–3 non iniziata, trace
owner vuoto. Otto identità contate; target e agenti assenti alla verifica.
Disattivare il grafico non basta a rendere ammissibile questa cattura.

Il default [senza strumenti](h100-followup-default-2026-10-10.md) resta
la misura del problema reale: 116 gruppi completi, aumento GPU di 511 MiB
con RSS e massimo native invariati, poi cap. I checkpoint asincroni e
NVML non identificano l’allocazione o il kernel responsabile. Questi
negativi della strumentazione non provano una causa del default né un
leak. La linea Nsight termina nella campagna; seguono i caller senza
profiler. Nessun cap o deadline viene aumentato.

Bundle nuovi verificati, manifest storici intatti:

- `h100-followup-profile-20261010T195900Z`: 27 file, 9.990.655 B,
  manifest `31868a5e6c0af0d4b4e7be05764c3f68de5dd83ef0d985778c2b9d9bbe194ca7`;
  include anche il ledger analitico coarser concluso.
- `h100-followup-component-20261010T200300Z`: 16 file, 196.247 B,
  manifest `add5c952538ef4ab000e75d6cdb104ef64765c2d4bfe3ffa43350b966b131027`.

Il totale privato conservato è 298.061.546 B, sotto il tetto 10 GB.
