# Scan lineare, XOF e candidate GPU — 9 ottobre 2026

Source `44acc7d49bf2b917bc8b9806e805a8774f255d70`, composto da `e7ac3f8`
(scan lineare), `6b5438c` (sali), `4f53fe6` (confronto Tensor) e `44acc7d`
(QK/PV). Baseline9033c64; Γ e semantica pinned rimangono invariati.
Il [record componenti](../../benchmarks/results/c71-crypto-components-local-2026-10-09-44acc7d49bf2.json)
ha SHA256 `17c70ea9c73bd0e02878a7b62842c43dea572ab6e2029b878db200e546ae352e`,
24 test Rust distinti/27 invocazioni e13 Python,68 artefatti,2 tracce
durevoli da295/294 record. Payload congiunto massimo delle prove ridotte
101.150.291 B; zero rifiuti. Ogni test60s/AS2GiB, un worker e processi
seriali; RSS massimo test/compilatori discendenti258.056.192 B.
La build preliminare56,91s/2.492.010.496 B è separata dal riuso Cargo
pulito identico. Nessuna compilazione o esecuzione CUDA/H100.

La closure lineare sceglie una scan originale per round invece della
enumerazione/getter del dominio. Prefissi EQ in chunk8bit, residual Cube
ordinati e punti borrowed; nessuna divisione/full-domain array o bitmap.
Wire, coefficienti, endpoint, FS e MAC originali coincidono su0/1/Fp3,
ordine reverse/rotated, forme sovrapposte, live pieno/parziale/zero.
Producer/coverage error falliscono prima delle correlazioni del round.
Lo scanner concreto rimane responsabile dell'unicità; confine range/count.
Tre rep D12full, stesso rootO0 binario e old-then-scan, danno rapporti
7,818/7,703/7,743 (media7,755), circa118ms→15,2ms del componente CPU.
Non è una misura della prova o H100. Visite D·live, public-tail0; EQ
≤ceil(D/8)·256 celle, residual72B/cube. D12 fixture heapbound13.656B,
forme borrowed1.424B, array oracle491.520B; altre fasi/model esclusi.

Sali: dominio34B inclusoNUL+seed32, input66B, XOF16word LE e counter64;
rejection/cap2^40, boundary dopo k accettati.56 vettori/7.168 byte e11
stream/66.308 foglie contro Rust pinned, incluso cloneMMCS a cursor32
con prefetch4096, seek/cap, commit consecutivi/clone successivo.
32768 maskcheck forzati; scratchmax10.520.320B, prescanW27.297.536B /
A23.103.232B. Hosthelper non esegue prefix/scatter CUDA. RNG176B(+32)
senza pubblica serializzazione; `live`+8B/API+16B conteggiati dal budget.
La build preliminare fallita per import RngExt e il comando python
assente exit127 sono dichiarati; nessun processo di test parte nel secondo.

Tensor: owner/stream/W/FFT/guard identici all'ordinario; confronto readonly
di tutte le word canoniche con4B D2H. Tre geometrie/128col/32coset,
digest postFFT esatti e12 arresti; comparewords1positivo/10arresti più
simboli obbligatori. Il driver differito non esegue MMA o CUDA. Context
37152B/Stats152B invariati; shared8448B candidato. La componente Q256
non è un'istanza canonica di hiding-rate. Il diagnostico reale preparato
usa W4MiB/R64/Q256 e non misura throughput del commitment pinned.

## Finding causale e correzione

La prima candidata QK/PV era numericamente esatta ma leggeva K/V fino al
massimo causale M16, inclusi futuri della prima riga. Il contratto vieta
anche letture di futuri già inizializzati: quelle premesse sono insufficienti.
Default scalare mai cambiato. `010b6b9` corregge QK con N8 nel prefisso
comune e bordo scalare; PV usa K32 comune e tail per output.
Il [record distinto a source29a257b](../../benchmarks/results/c71-attention-causal-local-2026-10-09-29a257b4476b.json)
ha SHA256 `283198cc215054aade7431a8c0555e5ee55827a1b033970798ac232eeb25b74a`.
Passa5 fixture con futureKV/Pi valide già inizializzate,44QK/61PVhead,
guard per ogni lettura MMA/scalare,18rifiuti marker,raw i128/RNE esatti.
Raggiunge bound232dot QK/M16,46tail/output e616prodotti PV/M16/lane.
Namedhost11.235.372B, shared/staging0; array interi nominali124B/thread
più raw8B, PiPointers256B. RSS132.485.120B,4,15s sotto60s/2GiB.
Non verifica codice macchina/registri/spill/scheduler GPU; non selezionata.

## Confini successivi

GPU sali: owner privato e `with_private_rng` sul cursore corrente; advance
una sola volta, buffer CPU invalidato, replay/hash sullo stesso flag sticky,
scratch/offsets ritirati prima di ring/valori. Conto candidato della fase
hash: current/descriptor/counter8.389.120B, banda device2.097.152B già
presente, rimozione hostband2.097.152B; delta+6.291.968B più metadata.
Indici privati boundedD2H24MiB W/20MiB A; elimina analiticamente128GiB /
64GiB upload sali e65536/32768fence, non tempi misurati. Prescan può usare
≤2^24candidati/chunk senza stima probabilistica di rejection. Nessuna
scan/ricostruzione aggiuntiva di A è ammessa da questa integrazione.

QueryA iniziale: riusare reader residente `window_native(runtime,0,0,...)`,
non il wrapper che riacquisisce il mutex. Una colonna/limb per volta,
staginghost≤8MiB, outputTree1GiB, fattoriGPU672MiB riusati per128col.
La previsione componenteGPU1.083.703.808B non è picco congiunto ammesso.
OddFFT/inverse natural-order e fattori distinti per child vanno integrati:
il vecchio factor kernel microbench usa lo stesso fattore per tutti batch.
Preservare richieste/windowcap, ordine/duplicati, padX^n e cache/root.
S1 richiede hook residenti35passaggi non-query e retention dopo apertura
del predecessore; evitare doppia copia3,22GB o caching anticipato oltre
budget. PCS v³=v+1 è distinta da MACu³=2, conversioni esplicite.

Il goal resta attivo: ownerXOF/query/S1/closureGPU, GKR/range, selezione
QK/PV e fusioni/sincronizzazioni secondo profilo, conto completo e
campagna pronta restano da completare localmente. La futura H100 richiede
nuova autorizzazione di hardware e durata. Nessuna fonte, Γ, benchmark o
milestone congelato è stato sovrascritto.
