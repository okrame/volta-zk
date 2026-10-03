# Consumer range A a finestre — 2026-10-03

Autorità: [design](../c7.1/design.md), [specifiche](../c7.1/specs.md),
[sicurezza](../c7.1/security.md). Segue il
[gather originale](canonical-range-gather.md), che da solo non era un prover.

## Collegamento e identità preservate

[`range/windowed.rs`](../../rust/volta-pcs/src/c71_matrix/range/windowed.rs)
ricostruisce inizialmente il canopy della stessa fraction tree dai byte
originali. Consuma il canopy dall'alto, poi usa le composizioni Gram già
selezionate nel [preflight](preflight.md), con retention finale dei quattro
figli per tail. L'ordine del reader è `[tail][prefisso][u][sottoalbero]`.
La geometria D34 usa taglio dieci, retention 24 bit e finestre 2 GiB;
il profilo ridotto D10 usa taglio nove e retention un bit, senza cambiare
polinomio o transcript del proprio dominio. D34 seleziona 26 passate;
D10 ne seleziona 22, incluse dodici finestre Gram e nove retention.

Per ogni tail, con figli `(p_u,q_u,r_u,s_u)`, il consumer accumula
`H[u,v] += Eq(tail) ((lambda p_u + q_u) s_v + lambda r_u q_v)`.
I fold MSB agiscono su entrambe le coordinate di H. La diagonale e i
due quadranti incrociati danno il polinomio quadratico dei prodotti;
il peso Eq della coordinata corrente dà gli stessi quattro coefficienti
cubici. L'uguaglianza del prefisso usa solo le sfide completate.
Le sfide future non stabiliscono gli indirizzi e il reader non riceve
campo, sfide, MAC o correlazioni.

La [`fraction tree`](../../rust/volta-pcs/src/c71_matrix/range.rs) mantiene
autenticazione, messaggi, prodotti e consumo delle correlazioni. Una variante
fallibile dei callback interrompe il percorso prima dell'autenticazione
successiva. I caller precedenti restano wrapper infallibili della stessa
routine, non una copia del protocollo. Il consumer non ha fallback scalare.

Il primo scan di un [`ReplayModel` byte](../../rust/volta-pcs/src/c71_matrix/b12/replay.rs)
conserva l'istogramma dei byte originali, aggiungendo il suffisso flat al
bin zero. Un scan incompleto, fuori range, non-byte o fallito non installa
i conteggi. Nessuna passata aggiuntiva è richiesta nel range per contarli;
le 512 ricostruzioni del commitment non aumentano. L'unicità degli indici
rimane una premessa interna del producer, supportata dalle bitmap e dal
layout canonico, non provata dal solo numero di emissioni.

Il [`runner canonico`](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_state.rs)
installa il reader riordinato sulla A appena impegnata.
[`SourceModel::range`](../../rust/volta-pcs/src/c71_matrix/gemma/native/protocol.rs)
sceglie il nuovo consumer per quella A; W e sorgenti senza reader mantengono
il riferimento precedente. Correlazioni, roots originali e verificatore
non cambiano.

## Risorse e confini

Il [record locale](../../benchmarks/results/c71-windowed-range-local-2026-10-03-0c3807f2fecb.json)
conserva 28 test Rust, 11 Python, build di libreria/runner, lint
correctness/suspicious e due rifiuti CLI attesi sulla revisione pulita
`0c3807f2fecb`. Non sono stati osservati test o build falliti durante questo
checkpoint; rimangono warning non bloccanti e parte dell'output dei lint
è stata troncata dal tool.

I positivi del nuovo range sono D10, con prefissi vivi 1/731/1.024 e
chiusura PCS sul commitment originale. Il dispatch del runner è esercitato
con getter scalare inutilizzabile. Le finestre eseguite sono al più
1.024 byte, non 2 GiB. Un reader che scambia due valori conserva histogram
e range ma viene rifiutato dalla PCS originale. Gli errori dopo la scrittura
del reader sono iniettati in tutte le 22 passate ridotte. I confronti
dei coefficienti includono sfide zero, uno ed extension e finestre di
512 byte. La regressione delle 512 scansioni D14 verifica anche il nuovo
istogramma senza passate aggiuntive. La prova integrata ridotta già
esistente usa ancora il suo range scalare: è una regressione della routine
condivisa, non un certificato completo che esercita il nuovo range A.

Non viene creato un albero completo D34 o un Eq(N) completo. I livelli
canopy terminano dopo il loro ultimo uso; H è rilasciata prima di allocare
i figli trattenuti. Le capacità dei figli rimangono dopo `truncate` e sono
incluse nel payload nominato del consumer. Le grandi allocazioni usano
`try_reserve_exact` e propagano il rifiuto. I contatori registrano passate,
finestre, byte richiesti e merge dell'albero. Non comprendono tutto il
lavoro Eq, Gram, producer, trasporto o allocatore, né le risorse simultanee
di preparatore, PCS, verificatore e Seed6. I contatori histogram originali
e la loro copia nella sorgente range sono capacità vive aggiuntive.

Questo è ancora un consumer CPU. La parità piccola non prova il lavoro o
il tempo D34 e non autorizza esecuzioni pesanti locali. Restano port CUDA,
range W, conto fisico completo, Γ reale e composizione canonica; gli
obblighi Seed6 restano aperti. Nessun certificato canonico, GPU, pesi reali
o spesa è acquisito. Il superamento analitico dei 40 MB nelle continuazioni
e l'hard stop provider non cambiano.
