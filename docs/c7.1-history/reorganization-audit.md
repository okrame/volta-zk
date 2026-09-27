# C7.1 — audit della riorganizzazione

Riorganizzazione del 2026-09-27, a partire da `5b293bc`.
La [documentazione corrente](../c7.1/design.md) è in cinque file;
la [mappa](README.md#conservazione-e-mappa-dei-percorsi) elenca 27 documenti
archiviati, con digest degli originali e del contenuto senza le
destinazioni dei link. I tre documenti congelati sono copie esatte.
Le prove e i risultati grezzi precedenti non sono stati modificati.

## Distinzioni rese esplicite

| Punto prima disperso nei documenti | Sede e interpretazione corrente |
|---|---|
| B12 matematico e Seed6 | [Sicurezza](../c7.1/security.md): teorema sul bootstrap originario; premessa EA-LPN autorizzata e composizione Seed6 ancora da chiudere |
| Calibrazione e misura della prova | [RunPod](../c7.1/runpod-tests.md): proposta 8 h / 40 USD senza autorizzazione; comandi CPU; audit indipendente mancante prima del congelamento |
| Stato canonico e controlli ridotti | [Design](../c7.1/design.md#stato-di-implementazione-e-lavoro-necessario): nessuna accettazione canonica completa attribuita ai test piccoli |
| Commitment iniziale PCS | [Specifiche](../c7.1/specs.md#pcs-e-ricostruzione-dei-valori): cache e pad conservati, senza ricostruzione iniziale a ogni proof |
| Campo cubico | Base MAC `u^3-2` distinta dalla base PCS `v^3-v-1`, con conversione e fixture del confine native |
| Parametri implementati e pianificati | Batch nativo 1.024 righe / Pow 256 distinti dal cap canonico; S1 riservato; due twiddle vivi |
| Memoria e tempi | Massimi nominati e limiti inferiori parziali distinti dal picco fisico e dal tempo completo |
| Dimensione del certificato | Limiti del parser 96/16 MiB distinti dai tetti 130/40 MB; bootstrap incluso solo nel certificato completo |

## Verifiche eseguite

Esecuzioni locali sul codice della base indicata, con sole modifiche
documentali e di percorsi di provenienza nel diagnostico. Working tree
non pulito: questi controlli non sono nuovi benchmark di riferimento.
Build mirate `volta-pcs --features c71-seed6-reference --lib --no-run`
e `--features c71-b12-pcs --example c71_calibration`, un job e target
canonico, completate con warning preesistenti. Test seriali, 60 s / 2 GiB,
Rayon/BLAS/OMP a un worker. Nessun checkpoint reale o dispositivo GPU.

| Gruppo Python | Esito |
|---|---:|
| `test_c7_1_gemma_plan.py -k 'B12 or canonical_PCS_wire or native_wire_body or complete_fixed_run or native_small_profile'` | 52 passati, 154 esclusi dal filtro |
| `test_c7_1_baseline_budget.py` | 9 passati, 1 fallito: audit fork descritto sotto |
| `test_c71_bootstrap.py` | 19 passati |
| `test_c71_calibration.py` | 14 passati |
| `test_c71_activation_pilot.py` | 8 passati |
| `test_c7_d126_gemma_native_bf16.py` | 5 passati |
| `test_c7_d126_gemma_weight_ingest.py` | 14 passati |
| `test_c71_query_remainder.py` | 3 passati |
| `test_c71_fft_microbench.py` | 7 passati |
| `test_c71_remainder_native.py` | 1 passato, otto fixture native |
| `test_c71_power_native.py` | 1 passato, dodici fixture native |
| `test_c71_arena_plan.py` | 12 passati |
| `test_c71_response_trace.py` | 5 passati |
| `test_c71_whir_trace.py` | 9 passati |
| `test_c71_pcg_trace.py` | 18 passati |

Nativi: passati i filtri `c71_b12_query_factors`, `c71_b12_query_remainder`,
`c71_b12_query_split`, `c71_b12_replay_base`, `c71_b12_retained_initial`,
`c71_b12_rational_power`, `c71_b12_full_sourcewise_chain`,
`c71_b12_native_canonical` (cinque test), `c71_b12_native_dispatch_canonical`,
`c71_b12_native_streaming_lookup_gkr_whir_positive_original_macs`,
`c71_b12_native_composed`, `c71_b12_native_registry` e
`c71_seed6_native_replay_w_and_ordered_a`: 17 test complessivi.
Gli ultimi due hanno inizialmente fallito perché il sandbox impediva
`UnixStream::pair`; ripetuti con la sola eccezione di esecuzione locale,
sono passati in 11,13 s e 32,66 s rispettivamente, senza rete esterna.

L'invocazione iniziale dell'intero `test_c7_1_gemma_plan.py` ha raggiunto
il limite locale di 60 s ed è stata interrotta. È conservata come
tentativo incompleto; il filtro mirato sopra è passato in 7,35 s.
Non si attribuisce alla suite completa un risultato positivo.

## Fallimento preesistente dell'audit del fork

`test_b1_rejection_preserves_failed_preflight_and_unknown_complete_costs`
attende 25 modifiche registrate, ma il censimento ne trova 26 su 96 file.
L'[audit](../../scripts/audit_c61_p3_fork.py) segnala:

```text
unregistered vendored source delta: merkle-tree/src/hiding_mmcs.rs
```

Il corpo originale di `scripts/c7_1_gemma_plan.py` letto direttamente da
`git show 5b293bc:scripts/c7_1_gemma_plan.py`, eseguito con il medesimo
percorso sorgente e senza modifiche ai fork, restituisce lo stesso risultato:
26 modifiche, 25 registrate, `source_guard_error: None`, stesso delta
non registrato. È quindi precedente alla riorganizzazione.

La riorganizzazione non modifica codice crittografico, lista dei delta
revisionati o aspettativa del test per ottenere un esito verde. Occorre
revisionare il cambiamento del fork e riallineare il registro dei digest
prima di dichiarare conclusa la verifica della provenienza corrente.
Il problema è riportato fra gli obblighi operativi nei documenti attivi;
non invalida retroattivamente il teorema matematico o trasforma una prova
ridotta passata in un'accettazione canonica.

## Controlli documentali

Il test [test_c71_docs.py](../../tests/test_c71_docs.py) controlla struttura,
link e ancore dei documenti operativi, dell'archivio navigabile e degli
ingressi, filtri nativi e conservazione dei contenuti archiviati. Controlla
anche la sintassi Bash e Python dei comandi RunPod senza eseguirli.
Quattro test passati; `git diff --check` passato. Il totale dei controlli
di codice è 177 test Python passati, un fallimento preesistente e 17 test
nativi passati, separatamente dai quattro controlli documentali.
I documenti congelati mantengono
deliberatamente la base dei link originale, ricostruibile dalla mappa.
Non si presenta la correzione dei link come un nuovo risultato di sicurezza.
