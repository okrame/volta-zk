# RMS: collegamento al runtime comune, 11 ottobre 2026

La preparazione usa lo stesso pod autorizzato e le deadline originali.
Owner default 42.280 B, +184 B per lo stato RMS. Sette allocazioni private
nell’arena comune contengono metadata, frame, assegnazioni, stage, Eq,
chunk512 e momenti fusi. Metadata di copertura e staging di pubblicazione
sono host addebitati; i fence precedono il riuso dei buffer e tutti i free
devono riuscire prima di pubblicare. Il consumer conserva il debito di
ownership incerta. Nessun nuovo transcript, endpoint o tipo di correlazione.

La scelta risolve la separazione del prototipo CUDA dall’owner del caller.
Il caller esplicito ricava il supporto dalle tile originali e passa i momenti
al GKR originale; la selezione canonica resta disabilitata. I primi quattro
round GPU lasciano fold/core residuo e conto simultaneo ancora aperti.
Supporto compilato, equivalenza del DAG parallelo, maschere, momento/Fp3,
lifetime e capacità restano premesse runtime, senza nuovo lemma Lean.

Il [primo trial pulito `369636be`](../../benchmarks/results/c71-certificates-rms-common-prefix-negative-2026-10-11-369636be.json)
fallisce prima della build Rust o della prova GPU: due compilazioni C++
rifiutano un’istruzione ambigua per `-Werror=misleading-indentation`.
Un test di algebra passa. Il negativo conserva 19 file/44.219 B, log e
monitor; non viene sovrascritto. L’istruzione di cleanup viene corretta
prima del nuovo checkout/trial. Zero certificati canonici.
