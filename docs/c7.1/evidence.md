# C7.1 — Evidence and validation

[Status](status.md) · [Design](design.md) · [Security](security.md) · [Decisions](decisions.md)

I risultati sono distinti per ciò che controllano. Un test finito supporta
la derivazione indicata; non dimostra da solo il teorema generale, la
corrispondenza del wrapper completo o la fattibilità hardware. Il diagnostico
conserva `credit:false` per gli screen e mantiene i campi storici dell'harness.

## Current mathematical result

Fonte: commit `9e57199`, 2026-09-10, [dimostrazione completa](security.md),
[diagnostico](../../scripts/c7_1_gemma_plan.py) e
[test algebrici](../../tests/test_c7_1_gemma_plan.py).
`complete_fixed_run_composition` conserva i bound razionali con l'envelope
aggiunto del caller; i valori decimali correnti sono nello [stato](status.md).
Le verifiche coprono anche traslazione dei pad sulle esposizioni della
stessa sorgente, storia accettata e assorbimento del token finale.

| Controllo a `9e57199` | Esito | Ambito |
|---|---:|---|
| `tests/test_c7_1_gemma_plan.py -k B12` | 49 passati, 154 esclusi | Algebra, contabilità delle riduzioni e composizione finita B12 |
| `tests/test_c71_bootstrap.py tests/test_c7_1_baseline_budget.py` | 29 passati | Bootstrap condizionale, budget e conservazione delle decisioni B1–B12 |
| `tests/test_c7_1_gemma_plan.py -k ideal_mac_simulation` | 1 passato, 202 esclusi | Coupling NoPeek riusato da G2 sui veri prefissi FS |
| CLI del diagnostico, default e self-check | passati | Report contabile e JSON valido, senza allocazioni Gemma |

Sono 79 controlli Python mirati. Non è stato eseguito un nuovo Rust E2E,
una build Lean o un benchmark per la chiusura matematica. Non trasformare
`conditional_mathematical_goal_complete` in ammissione del runtime o dell'hardware.
I risultati e le derive complete restano collegati anche al
[notebook congelato](../c7.1-gemma31b-design.md#b12-criterio-di-chiusura-composizione-completa-same-w).

## Native component evidence

Il [catalogo dei controlli nativi](../procedures/build-and-test.md#rust-and-resource-limits)
conserva filtri, casi negativi, dipendenze e limiti di esecuzione. I suoi
conteggi intermedi descrivono le singole fixture o fasi della costruzione;
non sono profili alternativi all'attuale composizione. Le derivazioni di
ciascun port restano nel [notebook B12](../c7.1-gemma31b-design.md#b12-pcs-unicità-del-messaggio-e-compilazione-privata).
Questa tabella indica come usare l'evidenza, senza ricopiare ogni sottoconto.

| Famiglia | Evidenza disponibile | Limite |
|---|---|---|
| B11 reale/AES e capacità B12 | Ruoli indipendenti, vettori AES/SHAKE, byte fault, seal, burn e arresto del pool | Componente bootstrap; non prova del wrapper Gemma |
| PCS salata/claimless, linear e range | Target originali, segni QuickSilver, falso target/padding respinti; piccoli casi con pool reale o MAC ideali | Configurazioni grandi solo pubbliche; nessun codeword D34/D35 materializzato |
| P0 e layout Gemma | 773 riduzioni compatte e route fisiche/virtuali; piccolo grafo raw con W/A ranged | Metadata e grafi ridotti; placeholder root non acquisiscono accettazione PCS |
| Byte/RNE/RMS/statistiche/lookup/gate-up/RoPE | Kernel e forme originali con casi avversari verso le stesse sorgenti | Profili e domini circoscritti; copertura numerica completa non equivale a esecuzione Gemma |
| QK/PV, residuali, KV | Link originale M→Pi, route O=0/150/300 e PCS fresche delle vecchie A | Le ricevute dei test KV sono ricevute di componente, non storia Gemma completa |
| Output/argmax/ratio/EXP30 | Output e softmax su byte originali; DV retag del dummy e rifiuti semantici | Accettazione del dummy è un controllo della simulazione, non da sola una prova ZK |
| Profilo comune e replay ampio | [profile.rs](../../rust/volta-pcs/src/c71_matrix/gemma/profile.rs), 421 profili/alias, produttori unici e punti MAC originali | Scale sintetiche, con controlli di copertura; non calibrazione del checkpoint |
| Ultimo preflight completo | `c71_b12_preflight`: tre contesti senza espandere le celle, riserva completa e rifiuto prima di getter/FS se capacità insufficiente | 11.187.057 righe base per quel profilo; GELU/softcap/RoPE sono placeholder di forma, non tabelle certificate |
| Ultime sorgenti flat | `c71_b12_flat_sources`: D11, 1.031 valori vivi signed/byte, target oltre indice 1.023 e padding alterato | D34/D35 verificati solo come profilo/framing; runner pubblico sempre n≤128/D14 |

L'upper conservativo del protocollo resta quello di
[security §6](security.md#6-risorse-riuso-formale-e-confine-runtime), non la
riserva inferiore del preflight sintetico. Il codice può accettare geometrie
pubbliche più grandi senza averne eseguito i corpi: distinguere guard del
compilatore, guard del runner e dominio realmente testato. Le vecchie
menzioni di D14/D15/D33 o 131.072 cubi non fissano il profilo completo corrente.

## Measured historical records

I file sotto sono immutabili e identificano il codice effettivamente misurato.
Sono risultati locali di componenti; nessuno è una misura del prover Gemma,
del traffico fisico completo o del protocollo composto attuale.

| Milestone e sorgente pulita | Record | Cosa conserva |
|---|---|---|
| B2 `de73f60` | [48×48](../../benchmarks/results/c71-b2-matrix48-20260908-de73f60.json), [128×128](../../benchmarks/results/c71-b2-matrix128-20260908-de73f60.json) | Due risposte matriciali e abort; tuple LPN piccole senza credito di sicurezza |
| B3 `84ab36c` | [census48](../../benchmarks/results/c71-b3-census48-20260908-84ab36c.json), [census128](../../benchmarks/results/c71-b3-census128-20260908-84ab36c.json), [timing128 separato](../../benchmarks/results/c71-b3-timing128-20260908-84ab36c.json) | Operazioni native, heap/RSS e tempi separati; prodotti base e cubic sono viste sovrapposte, non sommabili |
| B9 `fb6c787` | [3 righe](../../benchmarks/results/c71-b9-3-none-20260909-fb6c787.json), [32 righe](../../benchmarks/results/c71-b9-32-none-20260909-fb6c787.json), dieci fault nel budget | MR19/P-521 e COPE/Fp9→Fp3, nove frame e controlli dei due ruoli |
| B11 `8197f42` | [Registro dei dodici casi e relativi link](../c7.1-gemma31b-design.md#b11-selezione-intermedia-aes-a-capacità-finita) | Capacità 180/207 e dieci fault, con AES reale; non il profilo B12 completo |

[Archivio risultati](../../benchmarks/results/) e
[snapshot del ledger](../prototype-status-history-2026-09-10.md) conservano
anche run sporchi, fallimenti socketpair e diagnosi precedenti. I nuovi run
usano file nuovi; il riordino non corregge né sovrascrive questi record.

## Reproduce the narrow checks

Dalla root del repository, senza build Rust/Lean:

```bash
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_c7_1_gemma_plan.py -k 'B12 or ideal_mac_simulation'
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_c71_bootstrap.py tests/test_c7_1_baseline_budget.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/c7_1_gemma_plan.py
```

`pytest` è il tool uv globale; gli script usano `.venv/bin/python`.
Il report default mantiene l'harness dei goal a step. `--research-screens`
espone l'inventario storico, non ulteriori termini sommabili al risultato.
Per un cambiamento solo documentale bastano link, coerenza e diff; i
controlli sopra servono qui anche a verificare che il riordino conservi
il contratto del diagnostico. Le [procedure](../procedures/build-and-test.md)
restano l'autorità operativa per build, risorse e pulizia degli artefatti.

## Documentation reorganization validation

Base del riordino: `9e57199`, albero inizialmente pulito. La verifica finale
controlla: prova trasferita integralmente salvo link; snapshot identico;
corpo del notebook identico; percorsi/anchor citati da script e documenti
preservati; diff limitato alla documentazione e agli ingressi README/AGENTS.
Harness, script, test, Rust/Lean, fonti, benchmark e snapshot preesistenti
rimangono invariati.

Esito del 2026-09-10: **79 test passati** (50 B12/NoPeek, 29 bootstrap/budget),
CLI/self-check e JSON rigoroso passati; verificati i valori finali e i campi
dell'harness contro i documenti. I controlli di integrità sopra e dei link
locali/anchor passano, inclusi i riferimenti entranti dai documenti storici. Nessuna build Rust/Lean, esecuzione nativa o misura
nuova è attribuita al riordino. Le correzioni dei guard nelle procedure sono
riconciliate con il codice e i test sorgente attuali, senza rieseguirli.
