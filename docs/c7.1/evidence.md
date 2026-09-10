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

## Native bounded composition

Il 2026-09-10 il [wrapper nativo](../../rust/volta-pcs/src/c71_matrix/gemma/native/protocol.rs)
e il [preparatore](../../rust/volta-pcs/src/c71_matrix/gemma/native/prepare.rs)
sono verificati con otto [test Rust](../../rust/volta-pcs/src/c71_matrix/gemma/native/tests.rs)
e un controllo delle tabelle contro le ricette certificate Python. Si tratta
di verifiche di sviluppo su un grafo piccolo, con correlazioni Fp3 ideali;
non di benchmark su albero pulito, E2E AES o checkpoint Gemma.

| Controllo `c71_b12_native_…` | Proprietà esercitata |
|---|---|
| `prepare` | Tutte le 69 sorgenti, tre contesti, KV dell'ultimo token, ties-to-even e Stop della preparazione |
| `composed` | Tre certificati completi; digest FS uguali nei ruoli; 18 target W, 110 A, uno per vecchia A; riserve esaurite esattamente e promozioni concordi |
| `certificate` | Componente omesso/duplicato/riordinato, cardinalità RNE alterata, byte finali eccedenti, lunghezza ostile e Fp3 non canonico |
| `interrupted` | Troncamento dopo ciascuno dei 17 componenti del primo tentativo; tag finale PCS alterato; nessuna promozione e nessun riuso dopo Stop |
| `context` | W, predecessore, profilo, token, epoch e nonce diversi; replay di una risposta già accettata |
| `consistent_inference` | Calcolo interamente coerente con getter W alterati, mantenendo corpo e root W originali per range/PCS: rifiuto |
| `changed_predecessor` | K dell'ultimo token del predecessore alterata nel getter, con A precedente originale: continuazione respinta e registro fermo alla prima risposta |
| `exhaustion` | Capacità esaurita: Stop terminale, nessuna A pendente/promossa e nessun riavvio |

Il test positivo usa prompt 1 + generato 1 a O=0/2/4, un layer, hidden e
vocabolario 2, W Flat D10 e A Flat D12. Le 942/1.006/1.070 posizioni byte
vive includono tutti i produttori e gli istogrammi; padding fino a D12
verificato. Le PCS per risposta sono 2/3/4; W/A0/A1/A2 hanno 3/3/2/1
esposizioni. Le riserve sono 264.147/265.686/267.306 righe base equivalenti.
I certificati includono kernel, range, PCS, sali/path e framing: i byte
variano con le monete private, senza che questi test forniscano un bound
o una misura del certificato del modello completo.

Le mutazioni del certificato usano fork **solo nella fixture di test**
del registro già verificato e delle relative chiavi, per esperimenti
controfattuali sul medesimo certificato. Nessuna API di fork/import viene
esposta dal protocollo. I casi di getter W/KV alterati generano invece
nuovi certificati avversari e controllano i collegamenti agli originali.

Compilazione mirata `volta-pcs --features c71-b12-pcs --lib --no-run`,
offline/locked, opt-level 2 senza debug/incremental, un job, target canonico.
Ogni filtro sopra viene eseguito separatamente con `--test-threads=1`,
`RAYON_NUM_THREADS=1`, `timeout 60s` e `ulimit -v 2097152`.
Il [test Python](../../tests/test_c7_1_gemma_plan.py)
`-k native_small_profile` confronta GELU, softcap, EXP30 e tutti i sei
coefficienti Q30 con i generatori esatti esistenti. I campi canonici di
ammissione dell'harness rimangono falsi; `native_bounded_composition`
registra questo risultato separato.

Le 797.139 righe base del run composto non sono state espanse con AES:
quel bootstrap supera i limiti dei casi locali descritti nelle procedure.
La verifica positiva del port al pool reale e ai descrittori canonici resta esplicita nel
[design](design.md#native-correspondence). Nessuna esecuzione GPU/provider,
spesa, build Lean o build dell'intero workspace.

Validazione finale: **8 test nativi composti, 6 regressioni native e
81 controlli Python passati**, oltre a CLI/self-check, JSON rigoroso e
controlli documentali. Le regressioni native sono i tre
`c71_matrix::tests::`, `c71_b12_fs_uses_one_tape`,
`c71_b12_salted_merkle` e `c71_b12_real_durable_roles`.
Quest'ultimo ha inizialmente incontrato il divieto sandbox su socketpair;
è passato rieseguendo il solo caso locale con l'autorizzazione prevista
dalle procedure, mantenendo 60 s/2 GiB. Non è un fallimento crittografico.
Il filtro Python combinato è `B12 or ideal_mac_simulation or bootstrap or
budget` nei tre file di test indicati sotto; il controllo delle tabelle
è stato ricontrollato dopo aver adeguato il reader alla formattazione Rust.

## Native canonical and pool extension

Il [compilatore causale](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical.rs)
e l'[adapter reale](../../rust/volta-pcs/src/c71_matrix/gemma/native/pool.rs)
estendono il lavoro locale del 2026-09-10. Il goal resta aperto: questi
controlli non eseguono il preparatore/prover canonico né un'inferenza
composta positiva con AES. Nessun nuovo bound o credito hardware.

| Filtro Rust | Ambito |
|---|---|
| `c71_b12_native_canonical` | Tutte le 3.471 sorgenti hanno un solo produttore; 2.328 produttori ordinati causalmente, 773 P0, 421 RMS, 892 RNE, dieci alias K/V globali, tre contesti; sorgenti omesse/duplicate e ciclo respinti |
| `c71_b12_native_pool_packing` | Tre righe base→Fp3, negazione coerente di Delta, campo canonico e rifiuto di triple incomplete; mutazioni di W, semantica, sessione, seal, epoch, slot, predecessore e cursor |
| `c71_b12_native_pool_real_shortage` | Due ruoli con setup AES reale di tre righe, contesto verifier-owned e capacità insufficiente: Stop prima di prova/promozione, pool inutilizzabile e reopen rifiutato |

Il test con socketpair incontra nel sandbox il divieto di sistema ed è
passato fuori sandbox con gli stessi limiti locali. È un vincolo
dell'ambiente, non un fallimento di verifica crittografica. Non si è
espansa la capacità da 797.139 righe base. I percorsi positivi dell'adapter
sono compilati e condividono i kernel del wrapper ridotto, ma la sola
regressione ideale non ne verifica la composizione AES/journal positiva.
`native_canonical_producers` e i nuovi campi dell'adapter nel diagnostico
espongono questi limiti; le ammissioni canoniche/produzione restano false.

Validazione dell'estensione: **15 test Rust passati** (gli 11 filtri nativi,
tre regressioni lifecycle e `c71_b12_real_durable_roles`) e **81 controlli
Python passati** col filtro B12/NoPeek/bootstrap/budget già indicato.
CLI/self-check e JSON rigoroso passano; verificati link locali, formattazione
e diff. Passa anche `cargo check --lib` senza `cfg(test)`, quindi senza
gli ingressi ideali del wrapper. Build mirate offline/locked, un job, opt-level 2, target canonico
e configurazione `rust/.cargo`; ogni test è seriale entro 60 s/2 GiB.
Sono controlli di sviluppo, non benchmark su albero pulito o test dell'intero
workspace. Nessuna build Lean o esecuzione GPU.

## Canonical verifier body and prefix

Il [nuovo corpo](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_verify.rs)
implementa tutte le chiamate della schedule con i descrittori canonici;
riusa soltanto decoder e batch interni del percorso ridotto. Non è ancora
il wrapper canonico con proprietà del registro, né un certificato positivo.

`c71_b12_native_dispatch` passa a O=0/150/300: riserva vuota e profilo
alterato rifiutati senza modificare Fs; riserva ideale completa e frame
pubblico valido raggiungono il guard delle 773 coorti P0, che rifiuta una
prova con zero coorti. Il digest del prefisso coincide con la ricostruzione
delle quattro forme pubbliche e del frame; nessuna chiave è consumata.
Il riordino del primo frame rifiuta prima delle sfide. Le tabelle restano
quelle sintetiche del preflight (EXP30 esatto a e_score=128, le altre solo
di forma); nessun witness o codeword D34/D35 viene materializzato.

Il decoder conserva il cap ridotto di 16 MiB: il suo dimensionamento e
il framing dell'header derivato dal registro fanno parte del wrapper
canonico ancora aperto. La presenza delle chiamate a RMS, RNE, lookup,
attenzione e PCS nel corpo compilato non costituisce loro esecuzione
positiva congiunta. Il diagnostico distingue implementazione, prefisso
controllato e verifica positiva assente.

Validazione mirata: **3 test Rust passati** (prefisso e regressioni
`native_composed`/`native_certificate`), **2 test Python passati** col filtro
`complete_fixed_run or native_small_profile`, e `cargo check --lib` passato.
Stessi limiti locali e build mirata di cui sopra, senza nuove esecuzioni
AES, Lean, provider o hardware. Le evidenze precedenti restano distinte.

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
