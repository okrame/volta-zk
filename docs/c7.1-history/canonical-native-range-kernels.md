# Kernel range nativi CUDA — 2026-10-03

Il [record](../../benchmarks/results/c71-native-range-kernels-local-2026-10-03-4524ae60361e.json)
conserva dieci test Python (uno con 37 casi host), compilazione di undici
kernel sm_90, ptxas, SASS e hash della libreria sulla SHA `4524ae60361e`.
Gli artefatti binari e SASS sono conservati localmente sotto `benchmarks/raw`,
ignorato da Git. Nessun kernel GPU o prova Rust è eseguito in questo record.

Il port segue il [range signed/byte CPU](canonical-signed-range.md), con
le stesse tuple native Fp3 e senza accesso a transcript/correlazioni.
Le CTA operano su gruppi di al più 2.048 originali, non espandono una
finestra intera in un albero completo. Il root strided evita overwrite
fra thread; H ha fold su buffer distinti e riduzione in bucket CAS.
Il payload shared dei gruppi è al più 52.224 B. Il limite opt-in CUDA
per funzione è fisso, evitando che contesti concorrenti lo abbassino.
Il kernel coefficienti ha anche 216 B di stack locale per thread:
non sono spill riportati, ma restano memoria fisica da contabilizzare.

Il primo link fallì perché il runtime condiviso locale non era disponibile;
quello statico già presente risolve il link. Sono conservati anche due
errori degli strumenti: `/usr/bin/time` assente e `nvdisasm` non trovato
da `cuobjdump`. Il tempo shell e il PATH esplicito risolvono questi passi,
senza cancellare i log parziali. Nessuna modifica o download del toolkit.

Il prossimo passo locale è l'owner residente di stream/buffer, ledger ed
errori asincroni, quindi il collegamento ai callback Rust fallibili del
range e alla chiusura MAC originale. I launcher da soli non sono un runner.
CAS, Eq per indice, occupancy e stack non ereditano i tempi dello screen.
Restano gli altri consumer CUDA, la composizione canonica, Γ reale,
gli obblighi Seed6 e la contabilità simultanea completa. Zero certificati
canonici; il superamento analitico dei 40 MB e l'hard stop provider restano.
