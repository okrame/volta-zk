# C7.1 — sicurezza

[Design](design.md) · [Specifiche](specs.md) · [Test locali](local-tests.md) ·
[Test su RunPod](runpod-tests.md) · [Archivio](../c7.1-history/README.md)

Il [seguito RMS misto sul pod](../c7.1-history/h100-rms-moments-restart-2026-10-11.md)
è **attivo**: il proprietario autorizza il riavvio dello stesso
`z6wx2kkn69eoc0` alle **17:05:42 UTC** dell'11 ottobre. H100 originale
riverificata, idle all'accesso; nuovo guard indipendente prima del resume.
Finestra invariata: calcolo fino a23:43:00, guard00:03:00 e hard stop
12 ottobre00:13:00 UTC. La VM ha poche risorse: solo editing e controllo;
preparazione computazionale, test e build si svolgono sul pod.
Tre test F97 del prefisso misto e nove documentali passano sul checkout
pulito `f25452bf`; primo negativo documentale per fonti assenti conservato.
Il [censimento pubblico RMS](../c7.1-history/h100-rms-moments-census-2026-10-11.md)
passa replay parallel contro Booleano originale per159 programmi/99 profondità.
La [fixture onesta corretta](../c7.1-history/h100-rms-moments-rust-parity-2026-10-11.md)
passa parità composta wire/FS/MAC, acceptance RMS/PCS e alterazioni respinte.
Factor12→4 e assertion sul replay letterale risolvono sei celle invalide;
i due negativi e la diagnosi errata iniziale rimangono conservati.
Coefficienti Goldilocks, EXP30/decoder e check produzione passano;
prefisso Rust `cfg(test)`, max512 celle/pesatura per sorgente, correlazioni
ideali. Screen chunk32/batch4096: massimo nuovo payload130.378.444B;
conto traffico per tile superseduto dalla rettifica per batch preparata.
Prototipo CUDA con conteggi nei registri e chunk512 preparato, compilazione
H100 pendente; nessun piano contatori u32 globale o riga ausiliaria15.
Shared massimo40.896B entro232.448B H100; parità CUDA dei159 programmi,
runtime/caller comune, residuo fold/core e conto simultaneo restano aperti.
Distributività, selector/mask/wire, ricostruzione/count bounds/modulo,
determinismo dei frame e lifetime/capacità CUDA sono premesse non scaricate.
**Zero certificati canonici**: O=0 incompleto, O=150/300 non iniziati.
Backend RMS completo, conto simultaneo e premessa di raffinamento aperti.

La [prima fase della campagna certificati](../c7.1-history/h100-certificates-close-2026-10-11.md)
e il [seguito RMS](../c7.1-history/h100-certificates-rms-shared-cache-2026-10-11.md)
sono conclusi con **zero certificati canonici generati e verificati**.
O=0 resta incompleto; O=150/300 non sono iniziati. Il provider conferma
`EXITED` con runtime assente alle **14:27:28 UTC** dell'11 ottobre;
GPU idle prima dello stop e guard ritirato dopo la conferma.
Γ originale rimane ammesso, con nove input conservati riverificati.

Il seguito sullo stesso pod/H100 non ha cambiato la finestra originale:
avvio 07:31:18, termine calcolo 15:01:18, hard stop 15:31:18 UTC.
Riavvio alle 13:56:11, stop prima del guard aggiuntivo delle 14:39:15.
Nessun nuovo setup AES o runner canonico. Binario ed evidenze sono
conservati; il commitment A 512/512 della prima fase resta un componente.

Il [confronto pulito `bb7113ae`](../../benchmarks/results/c71-certificates-rms-shared-cache-2026-10-11-bb7113ae.json)
usa tutte le 159 ricette e 99 profondità su 511 celle sintetiche vive.
Cache folded 16 MiB e gate condivisi danno prover **192,665→158,589 s**,
−17,69% osservato in una sola coppia, verifier 6,568/6,604 s.
Wire 320.320 B con BLAKE3 uguale, FS/MAC originali e 9.919 correlazioni
ideali consumate. RSS/fisico stabile campionato 826.650.624/723.210.240 B;
GPU zero durante le prove, un campione incompleto nella candidata.
Sono esclusi modello, statistiche del caller, PCS, AES e risposta completa.

Le candidate restano disabilitate nel runner canonico. Il lavoro RMS
completo e la verifica fisica del conto simultaneo restano aperti: nella fixture l'endpoint
byte conserva 30.985.128 letture dei frame, non ridotte dai nuovi callback
di cella. Le premesse di raffinamento e Seed6 non sono scaricate da questa
misura; nessuna extrapolazione canonica o attribuzione del target 65 s.

Il [seguito RMS byte autorizzato](../c7.1-history/h100-rms-byte-paired-2026-10-11.md)
è concluso con **zero certificati canonici**. Il provider conferma
`EXITED` e runtime assente alle **16:48:04 UTC** dell'11 ottobre;
GPU idle prima dello stop e nuovo guard ritirato dopo la conferma.
Il [record AB/BA pulito `30867b9b`](../../benchmarks/results/c71-certificates-rms-byte-paired-2026-10-11-30867b9b.json)
conserva quattro prove CPU: 159 ricette/99 profondità, 511 celle sintetiche
vive più padding, cache16 MiB/gate comuni e byte0/1/1/0.
Prover medio **156,495→147,572 s**, −5,70% osservato; endpoint byte
**10,024→0,890 s**, −91,12%. Cella/replay e indici restano circa70/76 s;
wire320.320 B/BLAKE3 e9.919 correlazioni ideali uguali in tutte le prove.
Letture frame byte30.985.128→97.056; core/fold della cella invariati.
La variante aggiunge il budget evaluator32 MiB, stato osservato5.155.256 B.
A1/B1/B2 hanno GPU zero nei campioni; A2 e build registrano ciascuna15
occupazioni non attribuite fino a556.793.856 B. Nessuna attribuzione al
prover CPU, picco istantaneo o isolamento della coppia BA dedotto.
Modello, statistiche, PCS, AES e risposta completa rimangono esclusi;
nessuna selezione canonica o extrapolazione dal timing ridotto.
Il [record di chiusura](../../benchmarks/results/c71-certificates-rms-byte-close-2026-10-11-30867b9b.json)
conserva anche i primi poll con runtime ancora presente. Backend RMS
completo e conto fisico simultaneo restano aperti; dopo lo stop il
proprietario ha autorizzato il seguito sul pod riportato all'inizio.
L'avvio autorizzato16:13:00 e la deadline12 ottobre00:13:00 UTC restano
immutati dallo stop anticipato; nessun nuovo setup/sessione AES avviato.
Le [ricevute di avvio](../../benchmarks/results/c71-certificates-rms-byte-start-2026-10-11-30867b9b.json)
e il [piano pretrial](../c7.1-history/h100-rms-byte-followup-plan-2026-10-11.md)
restano conservati separatamente.
Un [oracolo locale RMS misto](../c7.1-history/local-rms-prefix-moments-2026-10-11.md)
verifica i primi cubici contro fold densi indipendenti, includendo wire
di altri programmi e selector originali. Tre test Python passano;
F97[u]/(u³−2), senza validazione Goldilocks/Rust, wire o nuovo lemma Lean.
La proiezione pubblica a4 bit dà64 maschere e417.792 B di momenti dopo
pesi/fusione; non è capacità completa o ammissione del builder.
Un layout BMMA non compresso con tutti i gate richiederebbe almeno
65.872.330.752 B di contatori a quella geometria: servono blocchi limitati,
conto di replay/pesatura/traffico e caller nativo prima di un nuovo trial.
Il [record pulito `47373d72`](../../benchmarks/results/c71-certificates-rms-phase-local-2026-10-11-47373d72.json)
conserva build, parità RMS mista e nove controlli documentali passati;
provider `EXITED` con runtime assente riverificato alle 15:33:09 UTC.

Il [ledger delle candidate RMS](../c7.1-history/local-rms-candidate-ledger-2026-10-11.md)
aggiunge fasi distinte per cache/gate e contrazione byte, conservando
CompactFrames, claim, Writer, PCG e VMM nello stesso conto. Addebita anche
1.918.464 B di proof/triple GKR trattenute prima non esplicitate.
Con VMM a 2 MiB e pool limitato ad A, il massimo RMS nominato è
5.028.218.943 B. I massimi generali per O=0/150/300 restano nelle query PCS:
margini rispettivi 82.643.566, 41.647.614 e **−29.066.098 B**.
È uno screen analitico di 659 fasi, `credit:false` e `joint_admitted:false`;
non risolve costo RMS completo, allowance fisica o superamento O=300.
Capacità Vec e lifetime Rust restano premesse di raffinamento; nessun
nuovo lemma Lean, selezione canonica o processo hardware.
Il [record pulito `bef98394`](../../benchmarks/results/c71-certificates-rms-candidate-ledger-local-2026-10-11-bef98394.json)
conserva 15 test del ledger, 9 documentali e lo screen bounded, tutti
passati; 31 artefatti con hash verificati, input storici invariati.

Una [contrazione byte a memoria limitata](../c7.1-history/local-byte-streamed-contraction-2026-10-11.md)
passa le parità locali di coefficienti e wire. Sostituisce le tabelle
per tutti i prefissi con pesi
Eq incrementali e sceglie il checkpoint dal supporto pubblico e dal budget:
8 MiB per stato, due stati durante il fold, upper dell'evaluator 32 MiB.
Conserva tutti gli otto livelli e recupera i figli originali da una nuova
lettura dei byte; non introduce endpoint o correlazioni diversi.
Dominio fino a 2^29 celle, al più 16 lane e 16.384 intervalli pubblici;
la selezione è solo nel benchmark RMS, default canonico disabilitato.
Distributività, somma unitaria di Eq, proiezione MSB del supporto e
lifetime/capacità Rust restano premesse implementative, insieme al
raffinamento della contrazione quadratica già esistente. Nessun nuovo
lemma Lean o credito di tempo/memoria canonici. Il test composto con
PCS termina al limite locale di 60 s e resta un esito negativo conservato.

Il [record pulito `63719021`](../../benchmarks/results/c71-certificates-byte-streamed-local-2026-10-11-63719021.json)
conserva quattro parità Rust, 23 controlli Python e il piano pubblico
bounded; 34 artefatti con hash verificati. Wire byte a 256 celle e wire
RMS mista coincidono con i riferimenti densi. Il timeout PCS non diventa
un pass; nessuna nuova misura H100 o selezione canonica.

La [candidata cache RMS](../c7.1-history/local-rms-fold-cache-2026-10-11.md)
usa solo righe già ottenute dalla sorgente originale e sfide già emesse.
L'identità affine e la distributività giustificano algebricamente il fold
incrementale; il mapping MSB degli indici Rust, l'aritmetica Fp3 e la
corrispondenza con i pesi Eq restano obblighi di raffinamento espliciti.
Il supporto pubblico non dipende da cancellazioni dei valori. Lifetime di
una sola profondità, rifiuto della cattura incompleta e consumo monouso
sono verificati su fixture; nessuna selezione o nuova garanzia canonica.

La [fattorizzazione candidata RMS](../c7.1-history/local-rms-shared-gates-2026-10-11.md)
partiziona i contributi originali per indice/gate e maschera dei programmi.
Le leggi di somma/prodotto del campo giustificano la riscrittura; sorting,
compattazione e associazione dei pesi Rust restano da raffinare. La scelta
fra le due valutazioni dipende soltanto dal supporto pubblico, non da
valori o cancellazioni. Non modifica transcript, monete, MAC, PCS o NoPeek.
La candidata non è selezionata nel runner canonico.

Il [preflight dell’11 ottobre](../c7.1-history/h100-certificates-preflight-2026-10-11.md)
conferma packed ed esponenti originali e conserva il replay di 512 cicli di
sole allocazioni grandi: nessuno spike riprodotto, controllo finale del
monitor negativo per census canonico assente. RMS/GKR esegue tutte le 99
profondità su 15 e 255 celle vive: prover 4,282 e 15,438 s, verifier 0,206
e 0,241 s, endpoint MAC/FS originali verificati. Cinque ricette Γ e frame
sintetici, esclusi modello reale, PCS, statistiche e setup AES: nessun tempo
canonico o target 65 s dedotto. Zero certificati canonici; lo spike A e
il costo RMS completo restano aperti. Il ledger con export ha massimo
nominato 5.878.767.874 B e 26.812.158 B residui, senza ammissione fisica.

I due componenti A diagnostici si fermano a
[41/512 gruppi](../c7.1-history/h100-certificates-a-physical01-2026-10-11.md)
e [15/512 gruppi](../c7.1-history/h100-certificates-a-physical02-2026-10-11.md),
con campioni fisici 6.530.682.368 e 6.487.887.360 B. Il secondo spike
compare dopo `cudaFree` di un buffer I64 da 4.915.200 B; stack CUDA
invariato a 256 B. GPU idle dopo ogni teardown, zero certificati.
Default: 16 filtri H100 passati; diagnostiche: trasformazione a owner
singolo passata, rifiuto del file esclusivo al secondo owner conservato.
Il nuovo esperimento di allocazione stream-ordered addebita 128 MiB di
cache prima dell’uso, controlla reserved/used e conserva i fence.
Owner 42.160 B e cap invariati. È **solo un diagnostico A**: la riserva
permanente supera il margine del ledger generale e blocca la selezione
canonica finché non viene ridotta o motivata con lifetime distinto.

Il [pool con riserva 128 MiB](../c7.1-history/h100-certificates-async-trace-2026-10-11.md)
passa tre parità H100 e arriva a **39/512 gruppi**, poi esaurisce i 16 MiB
di traccia. Nessuno stop fisico osservato: massimo campionato 6.062.788.096 B;
slack pool massimo registrato 86.097.152 B. Monitor finale negativo, GPU
idle dopo teardown. Il filtro corretto registra crescita esterna al backing
del pool già contabilizzato; controlli del pool e monitor fisico invariati.
Nessuna selezione canonica o root A completa; nove scenari simulati passano.

La [variante con lifetime limitato](../c7.1-history/h100-certificates-pool-phase-2026-10-11.md)
addebita il pool soltanto durante il commitment iniziale A e rimborsa dopo
fence e pool vuoto verificato. Owner 42.168 B, metadati Rust +16 B;
14 scenari simulati e parità locale A passano. Il [record locale pulito](../../benchmarks/results/c71-certificates-pool-phase-local-2026-10-11-25a6d958.json)
conserva i controlli e il ledger aggiornato:
O=0 5.890.193.534 B, margine 15.386.498 B; O=150/300 superano il
payload di 23.935.070/63.256.638 B. Variante ancora diagnostica,
nessuna selezione canonica o verifica H100 del nuovo lifetime.
Il [trial `a-async04`](../c7.1-history/h100-certificates-pool-physical-2026-10-11.md)
è terminato a 82/512 gruppi per stop fisico: 6.416.604.672 B. Pool backing
e RSS invariati nello spike, trace 458.216 B; GPU idle, zero root/certificati.
Il pool non risolve la crescita esterna. Il launcher CPU a 128 GiB è una
deviazione conservata; il monitor ora impone autonomamente AS ≤64 GiB.
Si valuta il backing differito delle colonne A di padding pubblico.

La variante diagnostica **`C71_SOURCE_VMM_EXPERIMENT`** riserva gli indirizzi
A/KV e rinvia il backing fisico delle code pubblicamente inutilizzate. Per
A O=0 differisce 29 colonne, 973.078.528 B, fino al ritorno del producer;
prima di padding/FFT/hash tutte le 128 colonne sono allocate e azzerate.
KV conserva handle condiviso, capacità logica 450 e contatore del prefisso:
inizialmente 150 righe, crescita prima dell’append che oltrepassa il backing.
Owner 50.848 B, 121 slot fissi da 72 B; ogni pagina arrotondata è addebitata
prima dell’allocazione, mai rimborsata con ownership incerta. Nessun nuovo
lemma Lean raffina il mapping driver: indirizzi stabili, fence, contabilità
e prefisso restano premesse implementative da verificare anche su H100.
Passano 22 scenari VMM simulati, regressioni default/pool e rifiuto dei fork
Rust; la variante passa anche le parità H100 descritte sotto, senza
selezione canonica.
Il [resoconto locale](../c7.1-history/h100-certificates-vmm-local-2026-10-11.md)
conserva ipotesi e limiti; nessuna root completa o certificato.

Il [record locale pulito VMM](../../benchmarks/results/c71-certificates-vmm-local-2026-10-11-abf57c4a.json)
conserva 11 test e gli screen alle granularità 64 KiB/2 MiB. Il massimo
nominato è 5.884.838.738/5.934.646.098 B: la seconda ipotesi supera il
payload complessivo di 29.066.066 B, pur lasciando spazio alle sei fasi
iniziali A. Granularità e lifetime reali devono essere verificati prima
della selezione canonica; nessun credito fisico da questi conti.

Il [preflight H100 VMM](../c7.1-history/h100-certificates-vmm-preflight-2026-10-11.md)
passa quattro parità: KV condiviso/duplicato, trasformazioni, A completa
ridotta e wire lineare FS/MAC originali. Granularità 2 MiB osservata,
CPU AS 64 GiB verificato, GPU idle dopo cleanup. Il distinto `a-vmm01`
è partito da O=0 con 5.400 s e cap invariati; interrotto per ritmo insufficiente.
Nessuna root del modello o certificato, RMS completo ancora aperto.

La combinazione diagnostica VMM + pool limitato ad A supera 45 scenari
host, compresa la chiusura del pool con KV differito ancora vivo: owner
50.880 B, riserva pool 128 MiB separata dal backing VMM. Il ledger richiede
una ricevuta esplicita di parità del lifetime combinato; nessun rimborso
VMM anticipato. `a-vmm01` è interrotto volontariamente per il ritmo di circa
61–65 s/gruppo, incompatibile con la finestra residua: non è uno stop fisico.
GPU idle verificata; il trial combinato segue le parità H100 riportate
sotto. Ipotesi: ridurre il costo delle allocazioni legacy durante il replay;
la causa del rallentamento non è attribuita. [Dettagli](../c7.1-history/h100-certificates-vmm-pool-2026-10-11.md).

Il [controllo pulito VMM + pool](../../benchmarks/results/c71-certificates-vmm-pool-local-2026-10-11-6ccb54a1.json)
passa 22 test, 29,80 s, AS 2 GiB. Alle sei fasi A restano da 51.235.582
a 1.142.302.058 B di payload; il massimo generale O=300 supera ancora il
cap di 29.066.098 B. Riserva pool 128 MiB solo durante A, owner 50.880 B;
nessun credito fisico o certificato dal ledger.

Il [preflight H100 combinato](../../benchmarks/results/c71-certificates-vmm-pool-preflight-2026-10-11-6ccb54a1.json)
passa KV, trasformazioni, root/aperture A e wire/FS/MAC lineare originali;
GPU idle dopo cleanup. Build CUDA 21,775 s, binari Rust riusati da
`abf57c4a` con produzione invariata e SHA conservata. Il
[trial `a-vmm-pool01`](../c7.1-history/h100-certificates-a-vmm-pool-2026-10-11.md)
completa **512/512 gruppi A O=0**: commitment 3.408,762 s, totale monitor
4.158,144 s. Massimo fisico campionato **5.861.006.848 B** sotto il cap
6.174.015.488 B, payload osservato 5.435.740.354 B; 20.746 campioni,
zero failure smaps. Pool chiuso, arena/W azzerati, allocazioni tutte
rilasciate e GPU idle. È il primo commitment A completo del modello;
**zero certificati canonici**. Restano esclusi W PCS/setup AES, prova,
verifica e continuazioni. Non dimostra il picco istantaneo o l’allowance
di tutte le fasi canoniche; il massimo analitico O=300 resta oltre cap.
Il confronto CPU RMS con tutte le 159 ricette è completato come riportato
sotto; il costo completo resta irrisolto. La variante VMM + pool resta
diagnostica finché non sono chiusi gli impedimenti del runner completo.

La [scansione incrementale dei pesi RMS](../c7.1-history/h100-certificates-rms-prefix-2026-10-11.md)
ricalcola soltanto il suffisso cambiato di Eq, senza divisioni. Passano
prefissi zero/uno, coefficienti densi e wire/FS/MAC della fixture mista;
il [record pulito](../../benchmarks/results/c71-certificates-rms-prefix-local-2026-10-11-55d58075.json)
conserva test, screen e ledger RMS +720 B. Questa modifica lasciava il
core a 844.006.203.160.300 prodotti; i callback restano invariati. Lo screen dei gate condivisi sulle 159 ricette è solo
un conto pubblico, non una riduzione implementata o un tempo completo.
Nessun nuovo lemma di raffinamento runtime; l’identità usa il prodotto Eq originale.

Lo [screen RMS con supporto originale](../c7.1-history/h100-certificates-rms-shared-support-2026-10-11.md)
ricostruisce il core precedente da 844.006.203.160.300 prodotti Fp3 e riduce
il beneficio ipotetico della fusione statica: 559.922.206.698.409 prodotti,
rapporto 0,663410, rispetto allo screen precedente a supporto completo.
Conservare i primi due round di quel checkpoint darebbe 542.419.458.937.257 prodotti.
Esclusi replay, fold, callback e costruzione; nessuna implementazione o
selezione, costo RMS completo ancora irrisolto. Controllo esaustivo dei
residui e tre screen locali bounded passano sulle 99 profondità; il
[record pulito](../../benchmarks/results/c71-certificates-rms-shared-support-local-2026-10-11-fe5f9d65.json)
conserva input, log e conti, RSS massimo 517.197.824 B.

Il benchmark RMS ignorato ammette ora tutte le 159 ricette originali e
512 celle ridotte, con dominio almeno doppio del numero di ricette e
una cella di padding. È un ampliamento della fixture, senza modifiche al prover;
serve a misurare tutte le profondità con il mix completo. Esecuzione
solo sul pod con timeout finito; nessuna extrapolazione a modello intero.

La candidata RMS a **tre prodotti agli estremi** riscrive il solo
coefficiente incrociato: `hi_x*hi_y - x*y - dx*dy`. Per AND/XOR generali
passa da sette a sei prodotti Fp3, compresa la ponderazione; primo round
Booleano invariato. L’identità segue `mul_add`, `add_mul`, `sub_mul` e
`mul_sub` nel campo; il raffinamento Rust/Fp3 resta una premessa, senza
nuovo lemma runtime. Stesse tre celle locali, nessun nuovo heap o messaggio.
Contatori e screen della candidata sono aggiornati; i conti storici
restano riferiti alla vecchia schedule. Le parità locali passano; la misura ridotta è riportata sotto,
senza selezione canonica o risoluzione del costo completo.

La candidata supera tre regressioni Rust: pattern Booleani esaustivi,
coefficienti contro fold densi e byte wire/FS/MAC originali della fixture
mista. Passano anche 22 controlli Python/documenti. Il core analitico con
supporto originale è 751.359.028.655.932 prodotti Fp3 per contesto,
92.647.174.504.368 in meno (10,98%); replay, callback e memoria invariati.
Nessun tempo completo dedotto. [Evidenza e limiti](../c7.1-history/h100-certificates-rms-endpoint-2026-10-11.md).

Il [record RMS pulito](../../benchmarks/results/c71-certificates-rms-endpoint-local-2026-10-11-04137d0c.json)
conserva tre parità Rust, 11 controlli Python/documenti e il census entro
AS 2 GiB/60 s. Binario compilato prima del commit con sorgenti identici,
provenienza distinta.

Il [confronto CPU sulle 159 ricette](../c7.1-history/h100-certificates-rms-all-recipes-2026-10-11.md)
completa entrambe le prove ridotte: 99 profondità, 511 celle vive
sintetiche più padding, verifier/FS/MAC originali e consumo di tutte le
9.919 correlazioni ideali. Prover baseline/candidata **194,166/191,238 s**,
verifier **6,577/6,602 s**, wire 320.320 B ciascuno. Una sola coppia:
−1,51% osservato, senza guadagno stabile o extrapolazione canonica.
I prodotti del core ridotto sono 1.321.999.818/1.176.979.554; i callback
restano 455.301. Nessun confronto byte-per-byte fra le due wire complete.
Il massimo RSS è 734.949.376/734.371.840 B; 15 campioni della candidata
registrano occupazione GPU non attribuita, fino a 556.793.856 B per circa
3,3 s. È inclusa nel conto fisico, massimo 1.218.600.960 B; nessun credito
GPU o isolamento della coppia. GPU idle finale, cap e AS rispettati.
Esclusi modello, statistiche del caller, PCS, setup AES e risposta completa.
Il core canonico resta analiticamente 751.359.028.655.932 prodotti Fp3;
nessun ostacolo RMS completo risolto, zero certificati canonici.

La [campagna precedente](../c7.1-history/h100-followup-close-2026-10-10.md)
è chiusa con provider EXITED alle 21:24:47 UTC del 10 ottobre e zero
certificati. Γ originale, pool e fill selezionati, geometria PCS,
NoPeek, MAC originali, PCG AES e correlazioni fresche monouso restano
invariati; RMS coarser resta respinto. I negativi seguenti ne conservano
lo stato di partenza e non sono risultati della nuova campagna.

**Zero certificati canonici.** Il [default](../c7.1-history/h100-followup-default-2026-10-10.md)
completa W/setup e 116/512 gruppi A, poi supera il cap fisico:
6.545.690.112 B contro 6.174.015.488 B. Step GPU 511 MiB con RSS
costante e massimo native osservato invariato. Le [catture Nsight](../c7.1-history/h100-profiler-limit-2026-10-10.md)
si fermano prima del primo gruppo; nessuna timeline dello spike.
Il [componente A](../c7.1-history/h100-followup-callers-2026-10-10.md) senza
PCS W/setup AES supera anch’esso il cap dopo 33 gruppi: 6.494.850.560 B,
step GPU 496 MiB. Questo stato canonico non è necessario al negativo di
componente; allocazione/kernel responsabile e allowance restano aperti.

Le [tre inferenze reali](../c7.1-history/h100-followup-inference-2026-10-10.md)
passano i 150 token ammessi: 85,144/76,760/77,050 s senza pool/solo
pool/pool+fill. Pool −9,847% osservato in una coppia, stesso traffico,
lanci e fence; 1.185.769 allocazioni in meno. I sei confronti A alternati
sono conclusi: gruppi 1–4 comuni, pool −0,148% e fill −0,323% osservati,
più piccoli della variazione fra ripetizioni. Nessun guadagno A stabile;
13.667 alloc/free e 3.840 lanci applicativi evitati per gruppo sono esatti.
Il pool è selezionato per l’inferenza; il fill resta semplificazione esatta
senza credito di wall stabile. Nessun A/root completo o picco congiunto.

Il [confronto SDPA completo](../c7.1-history/h100-followup-optimized-2026-10-10.md)
misura 2,420–2,634 s per risposta BF16 originale e 2,493–2,687 s
per i16→BF16, a O=0/150/300, load e warmup separati. Tutti i 357 raw
head per precisione sono finiti; token floating divergenti, nessuna
parità intera o selezione nel protocollo. Il primo loader fallito resta
conservato, corretto con i bit pubblici dei 60 scalari.
Lo [screen RMS coarser](../c7.1-history/h100-followup-rms-2026-10-10.md)
termina senza errore ma concorda con 2/50 token generati O=0, prima
differenza alla terza decisione: criterio pretrial respinto, linea fermata,
O=150/300 non avviati. Inferenza 77,210 s; nessuna ammissione o qualità
generale dedotta dal confronto. Γ originale resta l’unico ammesso.
Compiler 159→91 e possesso dei programmi ridotto sono componenti;
qualità, GKR e tempi completi non derivano da questi risultati.
CPU wrapper AS 64 GiB, solo il figlio CUDA senza cap AS. I nuovi caller
attendono GPU idle dopo teardown, senza nuova esenzione W o cap aumentati.
Journal e correlazioni non sono riusati; cause, bound e target 65 s aperti.

I consumer PCS iniziale, residual e closure lineare limitano gli span
al prefisso `initialized`, rifiutando coda non scritta, overflow e contatori
oltre capacità. Il driver deve descrivere un prefisso contiguo scritto
prima della lettura. Nessun lemma Lean raffina questo contatore C++:
è una premessa implementativa esplicita, sostenuta dalla
[regressione prima/dopo](../c7.1-history/h100-prefix-candidate-2026-10-10.md)
e dalla [parità H100](../c7.1-history/h100-prefix-validation-2026-10-10.md).
Valori, ordine, copertura originale, NoPeek e MAC restano invariati.

La [chiusura locale del 10 ottobre](../c7.1-history/local-exploration-close-2026-10-10.md) riguarda implementazione e screening numerico locali.
Il flag numerico sincrono riusato viene azzerato prima di ogni producer;
restano tutte le letture di errore, fence e guardie necessarie prima della
pubblicazione. È privato e conserva capacità addebitata fino al cleanup;
i flag sticky PCS/byte sono distinti. Errori aritmetici, launch, copie,
fence e cleanup falliti restano terminali. La verifica col driver simulato
non fornisce parità CUDA reale o un lemma Lean di raffinamento.

Gli screening di quattro scale A alternative non ereditano l'ammissione
Γ e non cambiano il protocollo selezionato: NoPeek, MAC originali,
correlazioni monouso e PCG AES restano invariati, senza prove/PCS per token.
W, architettura, workload e ricette numeriche sono fissati; variare scale
cambia la relazione e richiede i controlli numerici/qualità e l'ammissione
completa, più il ricalcolo delle prenotazioni e dei bound applicabili.
Il [piano hardware mirato](../c7.1-history/local-hardware-plan-2026-10-10.md)
era coperto dall'autorizzazione della campagna ora chiusa, entro il suo
ambito e termine; le candidate Γ restano screening non ammessi.

L’export del certificato è diagnostica privata, successiva alla costruzione
del corpo; non modifica wire, transcript, sfide o correlazioni. Il file
`response-SLOT.bin` non implica verifica: il record `acceptance-SLOT.bin`
è scritto solo dopo il successo del verifier e del suo journal durevole.
Un errore di export termina la sessione senza riuso. Nessuna chiave DV
o correlazione è esportata; il bundle non introduce verifica pubblica,
resume o un nuovo lemma di raffinamento.

La traccia fisica diagnostica aggiunge solo metadati di risorsa pubblici
ai confini owner e termina su query/scrittura fallita. Non altera relazione,
coin, capacità private o endpoint; le query possono alterare il timing e non
dischiudono l’assunzione di raffinamento Rust/CUDA né il bound fisico completo.

## Ambito e ipotesi

Il [preflight del seguito H100](../../benchmarks/results/c71-h100-followup-preflight-2026-10-10-7b0885ad316f.json)
conserva Γ/W byte-identici e controlli CUDA finiti sulle tre librerie.
Il cap del logger ferma il primo replay diagnostico; cleanup diagnostico
e lifecycle W non ricevono credito. La variante esplicita delle sole
alloc/free da 1 MiB conserva snapshot e cap, e richiede eventi CUDA
esterni per la copertura omessa. Non abilita prosecuzione del run fallito,
rilassamento dei limiti, ammissione o raffinamento generale.

I §§1–6 definiscono e dimostrano la composizione matematica
`C71B12-Gemma-FixedRun-v1` sul bootstrap B11/B12 originario. Il percorso
efficiente Seed6 conserva la relazione di inferenza, ma richiede il
trasferimento di sicurezza descritto nell'ultima sezione. La correttezza
di test finiti e la corrispondenza generale del programma al protocollo
sono risultati distinti.
La campagna verifica parità finita CUDA e conserva la composizione
prevista: NoPeek, endpoint nei MAC originali, AES reale e correlazioni
monouso. I [trial terminali](../c7.1-history/h100-canonical-06-2026-10-10.md)
non promuovono KV o ricevute; journal, monete e capacità prenotate non
vengono importati in nuovi trial. Γ e pesi immutabili hanno un ciclo di
vita distinto dal setup di sessione e possono essere riusati dopo verifica.

I diagnostici `inference-cuda` e `commitment-a-cuda` non producono
accettazione, prova MAC o continuazione. Le correzioni di marker pubblici
non selezionati e prefisso KV ripristinano la semantica originale; marker
selezionato, accesso non inizializzato e overflow restano terminali.
Le [parità reali](../c7.1-history/h100-prefix-validation-2026-10-10.md)
sono evidenze di implementazione, non un raffinamento generale o credito
al teorema. THP, stack e code sono configurazioni operative: nessuna nuova
esenzione di memoria o ipotesi crittografica, e nessun rilassamento dei cap.
Il [guadagno del setup](../c7.1-history/h100-setup06-checkpoint-2026-10-10.md)
non modifica il traffico o il trasferimento dei bound a Seed6, ancora aperto.

La candidata cGGM con coda XOF differita conserva il frame, gli offset
0/64/128 dei tre slot e gli otto tentativi per slot. Dopo un candidato
accettato del terzo slot, i byte rimanenti non hanno consumatori: ogni H
usa un nuovo reader. I test confrontano il campionatore completo e tutti
i numeri di scarti fino a esaurimento. Nessuna correlazione è riusata;
i bound logici di 192 byte per H rimangono conservativi. Questo argomento
locale non chiude il raffinamento generale Seed6 o la sua composizione.

Il teorema richiede almeno 78 bit per ciascun vantaggio completo.
Si lavora nel modello dell'oracolo casuale classico, con lavoro e memoria
dell'avversario `T_A=M_A=2^80`, inclusi ambiente, preprocessing e advice,
e `Q_A=2^64` query globali, inclusi candidati Fiat–Shamir scartati.
Le riduzioni restano sotto `T_R=2^121`, `M_R=2^93`, `Q*=2^74`.
A queste risorse si assumono vantaggio AES-256 PRP a quattro blocchi
≤2^-128 e vantaggio DDH P-521 ≤2^-193. Sono ipotesi concrete dichiarate,
non garanzie dedotte dai nomi delle primitive o dai loro test.
Non si assume un setup onesto aggiuntivo.

La riduzione PCS usa distanza del codice e accordo multiplo con
`3*tau<d`, decodifica entro il raggio di unicità, Merkle salato e
preimmagini differite, blocchi di monete Fiat–Shamir e chiusura scalare
nel MAC originale. Non assume una congettura di decodifica a lista.
I parametri sono in [specs](specs.md#pcs-e-ricostruzione-dei-valori).
Le derivazioni componenti riutilizzate sono:

| Risultato | Derivazione, applicata con i parametri correnti |
|---|---|
| Bootstrap reale → ideale e seal | [AES a capacità finita](../c7.1-history/c7.1-gemma31b-design.md#b11-selezione-intermedia-aes-a-capacità-finita), [risorse e seal](../c7.1-history/c7.1-gemma31b-design.md#b12-risorse-lifetime-e-vincolo-same-w), [setup unico](../c7.1-history/c7.1-gemma31b-design.md#b12-capacità-aes-iniziale-per-il-run-continuo); S=1 e M93 |
| Unicità del messaggio PCS | [RS/Merkle e chiusura privata](../c7.1-history/c7.1-gemma31b-design.md#b12-pcs-unicità-del-messaggio-e-compilazione-privata) |
| Privacy delle aperture su endpoint condivisi | [Traslazione congiunta](../c7.1-history/c7.1-gemma31b-design.md#b12-zk-del-consumer-claimless-nel-run-continuo), applicata nel §5 |

Questi rimandi identificano derivazioni, non importano i profili intermedi
o le istruzioni operative dell'archivio. Il conto eseguibile completo è
`complete_fixed_run_composition` in
[c7_1_gemma_plan.py](../../scripts/c7_1_gemma_plan.py).

## 1. Enunciato e oggetti fissati

Il protocollo qui definito compone le componenti B12 già analizzate.
Sotto le ipotesi primitive B12, nel ROM classico, contro avversario e
ambiente con lavoro/memoria inclusi preprocessing e advice ≤2^80 e query
RO globali ≤2^64, valgono:

1. **Soundness del run.** Salvo probabilità ≤ε_S, esiste **un solo W
   estratto all'installazione**, in i16 simmetrico, tale che ogni risposta
   accettata e ogni sua coda KV sono l'inferenza intera specificata su W
   e sul precedente stato accettato. L'estrazione è della riduzione;
   il verifier ordinario non riceve W.
2. **ZK del run.** Esiste un simulatore senza W, con gli output consentiti
   dell'ideale e lo stato Delta/chiavi del verifier corrotto nel gioco
   bootstrap ideale, la cui vista dista da quella reale al più ε_Z.
   Sono inclusi installazione, richieste adattive, query RO e ogni prefisso
   fino alla terminazione, anche se nessuna risposta viene accettata.

I bound razionali sono quelli di `complete_fixed_run_composition` nel
[diagnostico](../../scripts/c7_1_gemma_plan.py): **82,93261 bit soundness e
91,02272 bit ZK**, entrambi oltre 78. Sono teoremi condizionali alle
ipotesi AES-256/P-521 già dichiarate a T121/M93; non sono concrete
dimostrazioni di sicurezza di AES/DDH. Non si aggiunge un setup onesto.

Il profilo selezionato ha un'installazione W/D35, un setup AES iniziale,
un key epoch, tre tentativi totali, 100 token di prompt e 50 generati per
tentativo, O=0/150/300. Errore, abort o esaurimento termina il run.
L'ideale restituisce i token della semantica deterministica selezionata,
oppure un solo esito `Stop` se la preparazione privata non può completarla.
Non espone layer, celle, valori intermedi, ragione privata o progresso
della preparazione. Le lunghezze e l'ordine dei messaggi di prova sono
pubblici; tempi fisici, accessi memoria e side channel non sono il transcript
matematico qui simulato. Lo schedule fisico resta da ammettere.

La tesi ZK parte da una **nuova installazione onesta** del modello privato,
che il simulatore può simulare. Non equivoca una root arbitraria fissata
esternamente prima del gioco. La soundness accetta un modello privato
installato dal prover: non ne attesta la provenienza da un checkpoint.

Il parametro pubblico Γ contiene, in forma canonica e senza campi scelti
dalla prova:

- DAG/metadata/layout pinned, i 772 tensori fisici e l'alias embedding/head;
- esponenti e ricette di `Recipes::compile`, epsilon RMS positivo, scalari
  BF16 esatti, RNE con overflow reject, argmax a parità risolta sull'ID minimo;
- tabelle certificate GELU/softcap, Q30 alle posizioni assolute ammesse e
  `C71-SOFTMAX-EXP30-v1`, con e_Pi=-14;
- i profili PCS flat D35/D34, alphabet/range/padding, capacità iniziale,
  ordine di verifica definito sotto e limiti pubblici dei kernel.

Si prepara e valida Γ **prima dell'installazione autenticata di W,
del bootstrap e della prova**. La lettura dei pesi per la calibrazione
offline precede quell'installazione e non usa correlazioni di sessione.
Le tabelle sono
quelle attese dal verifier, derivate dalle ricette certificate; confrontare
un digest fornito dal prover non certifica una tabella. Il teorema è
parametrico in Γ valido; scegliere/calibrare Γ del checkpoint reale non
è una premessa crittografica nascosta. Lettura, controllo delle dimensioni,
compilazione e hashing del parametro sono contati nel §6; la ricerca di
una calibrazione è fuori dal protocollo. Descrittori interni sono quelli
ricompilati dal verifier, non oggetti `Sources` o `Recipes` importati dal
certificato. Nei confronti di stato si conservano le identità complete;
i digest sono nomi nel transcript, non una fonte di autorità separata.

L'accelerazione offline FP64 può cambiare l'ordine delle somme: il bound
numerico verificato su fixture/prefissi non implica uguaglianza bitwise
né sostituisce l'ammissione intera. I kernel C11 indipendenti e Rust/CUDA
hanno controlli di overflow/marker e confronti finiti; non esiste un lemma
Lean che raffini queste implementazioni. Il driver C11 non condivide il
kernel matriciale Rust/CUDA né i suoi risultati; il confronto completo
resta esatto su tutti i frame, e precede qualsiasi bootstrap o prova.

## 2. Preparatore e macchina di accettazione

**Preparatore onesto.** `Prepare(W, Γ, accepted_private_KV, prompt)` esegue
la semantica intera nell'ordine causale, genera i 50 token e completa K/V
del token finale, senza emetterne un cinquantunesimo. Materializza W e A
nel layout flat dichiarato, tutti i raw, byte biased e istogrammi richiesti.
Il suo input non contiene Delta, tag, correlazioni, seed PCS o sampler FS.
Il risultato è uno snapshot immutabile; nessun getter della prova può
ricomputare un'altra quantizzazione o leggere correlazioni non consumate.
Se fallisce, emette soltanto `Stop` prima della root A e di ogni messaggio
di prova. L'algoritmo astratto ammette la materializzazione densa; questo
non la rende compatibile con la memoria hardware obiettivo.

Le valutazioni dopo una sfida leggono esclusivamente questi snapshot e
le sfide precedenti. La casualità delle PCS è separata dalle righe MAC.
`Authenticate(v)` prima calcola v, poi consuma la prossima riga del
sottointervallo assegnato; prodotti e shift PCS consumano maschere proprie.
Questa è la definizione del prover composto, non una proprietà assunta
per ogni closure Rust che possa essere passata alle API dei componenti.

**Stato del verifier.** Dopo installazione/setup:

```text
S = (Γ, C_W, session, key_epoch, capacity_seal, cursor, next_slot,
     accepted = [], live = true)
accepted[j] = (j, O_j, C_Aj, canonical_A_layout_j, tokens_j, receipt_j)
```

Solo la procedura seguente può aggiungere un elemento ad `accepted`.
La sessione conserva anche le chiavi e la capacità finita del bootstrap.
Il prover non fornisce una lista di ricevute da importare nel registro.
Una richiesta nuova si riferisce all'ultimo elemento del registro, oppure
al predecessore vuoto iniziale. Non si sceglie un ramo con una ricerca
per digest. Le A vecchie rimangono sorgenti immutabili di code, non nuove
root attivabili. L'ACK non modifica questo registro.

`VerifyResponse(S, prompt, tokens, C_A, certificate)` è il seguente
algoritmo deterministico con la chiave DV e l'oracolo FS pubblico:

1. Se `!live`, non eseguire altro. Altrimenti impostare subito `live=false`:
   qualunque uscita anticipata conserva lo stato terminale. Controllare
   `next_slot=accepted.len()<3`, sessione, epoch, seal, nonce, predecessore,
   C_W immutabile, prompt di 100 token e token pubblici di lunghezza 150
   con quel prefisso; ogni ID è nel vocabolario. Ricompilare le sorgenti
   a O=150*slot da Γ. C_A deve essere fresca, distinta da W e dalle A
   precedenti. Confrontare Γ e profili con quelli conservati.
2. Calcolare `Recipes::required` dai dati pubblici e riservare una volta
   l'intero intervallo contiguo di righe, nella capacità iniziale. Bruciare
   slot/intervallo **prima** di accedere a quelle righe o a messaggi di prova:
   avanzare `cursor` di `3*required` righe base e `next_slot` di uno.
   Nel transcript iniziale di dominio `C71B12-Gemma-FixedRun-v1` inserire
   Γ, C_W, tutte le identità del registro in ordine, C_A, sessione/epoch/seal,
   slot/intervallo/nonce, prompt e tutti i token. Ogni vettore ha lunghezza
   e encoding canonici. I record dei componenti sono poi concatenati in
   questo **unico Fs**, senza ripartire da transcript locali.
3. Eseguire esattamente la schedule del §3. Il certificato è il prodotto
   ordinato delle prove indicate, con cardinalità fissate, non una lista
   di moduli opzionali. Qualunque errore, prova mancante/eccedente, forma
   invalida, chiave mancante o superamento di capacità/draw termina il run.
   Consumare ogni MAC originale restituito nel batch indicato.
4. Eseguire tutte le PCS finali del §3 e consumare esattamente la riserva.
   La chiusura è il successo congiunto di **tutte** le verifiche, non la
   sola ultima PCS. Verificare framing finale ed esaurimento del certificato;
   assorbire un record finale di completamento in Fs. `receipt=Fs.digest()`.
5. Aggiungere atomicamente `(slot,O,C_A,layout,tokens,receipt)` al registro,
   rendere visibili i 50 token come verificati, impostare `live=true` se
   resta uno slot, altrimenti terminare con tre risposte accettate.

Il framing esterno univoco è parte dell'algoritmo matematico. Il codice
implementa codec e wrapper canonici interni; i controlli strutturali
non costituiscono una verifica positiva dell'intero modello. Un errore restituisce al peer
solo `Stop`; i messaggi di errore dettagliati interni non sono wire.
Il [trasporto dell'accettazione](specs.md#dati-autenticati-e-stato) lega il
completamento alla ricevuta e al certificato pendenti: non è un nuovo
meccanismo di autenticazione. Nel runner CPU i due ruoli usano socketpair
create localmente; un trasporto distribuito deve fornire la premessa di
autenticazione, non sostituirla con il solo hash del certificato.
Una perdita del processo termina il run; non si invoca `reopen`.

## 3. Schedule completa e destinazione degli endpoint

Notazione: `s` è il `P0Statement` ricostruito da S; `r`, `a`, `o`, `m`
sono rispettivamente le sorgenti residuali, attenzione, output e softmax
ricompilate; `b` è la stessa `Bytes` finale da 3.471 sorgenti.
`BW`, `BA`, `BOld[j]` sono liste inizialmente vuote di coppie (forma,key).

Un risultato `(forms,bias,originals)` viene aggiunto come
`(forms[i], originals[i]+Delta*bias[i])`. Il prover usa lo stesso valore
originale più il bias, mantenendo il tag. Non si autentica nuovamente il
valore. Una forma pubblica `(form,bias)` usa `Key(Delta*bias)` e,
nel prover onesto, `Auth(bias,0)`. Le liste non provengono dal certificato.

L'ordine completo è il seguente; le chiamate sono le funzioni matematiche
realizzate dai kernel collegati, con i loro controlli/gradi attuali:

| Ordine | Verifica / compilazione | Destinazione obbligatoria |
|---|---|---|
| 1 | `b.affine_zero_form(plan,s,recipes.affine)`, `b.argmax_zero_form`, `a.mask_zero_form`, `m.zero_form` | Quattro target pubblici in BA; argmax usa `tokens[100:150]` e la Y softcap originale |
| 2 | [`plan.verify_p0`](../../rust/volta-pcs/src/c71_matrix/gemma/caller.rs) su 773 coorti; include il batch prodotti | `weight_forms/weights` in BW; `b.forms(plan,p0)` con cuts e inputs originali in BA |
| 3 | [`rms.verify_rms`](../../rust/volta-pcs/src/c71_matrix/gemma/rms/caller.rs) con le 421 ricette comuni | `rms_forms(pending)` in BA: S, entrambe le X originali per statistica e byte P/S/Y congiunti |
| 4 | `recipes.original_rne(plan,r,p0,norms)`, poi [`rne::verify`](../../rust/volta-pcs/src/c71_matrix/rne.rs) per ciascuna delle 410 richieste nell'ordine del compilatore | Passare **la key e il punto originali** della richiesta come target; aggiungere il MAC byte restituito con `source_rne_form(request.source,point)` in BA |
| 5 | `pairs=recipes.table_pairs(plan)`; [`b.verify_table_rne`](../../rust/volta-pcs/src/c71_matrix/gemma/bytes/quantize.rs) sulle 482 coppie | `table_rne_forms(plan,pairs,pending)` in BA, output e raw originali |
| 6 | [`gelu.verify_lookup`](../../rust/volta-pcs/src/c71_matrix/gemma/gelu.rs), tabelle attese | `gelu.forms(point)` e le tre `originals` X/Y/M in BA |
| 7 | [`gate_up::verify`](../../rust/volta-pcs/src/c71_matrix/gemma/gate_up.rs) sullo statement canonico unico | `gate_up.forms(raw_point,input_point)` e i tre originali R/G/U in BA |
| 8 | [`rope::verify`](../../rust/volta-pcs/src/c71_matrix/rope.rs) sullo statement delle 120 route Q30 | `rope.forms(raw_point,input_point)` e i due originali R/Y in BA |
| 9 | Per layer 0..59: [`attention::verify_qk`, `verify_pv`](../../rust/volta-pcs/src/c71_matrix/attention.rs) sullo stesso statement canonico; PV include il link del contratto M alla Pi originale | `a.qk_routes` e `a.pv_routes`: raw/Q e raw/Pi in BA; conservare in ordine K,V nelle 120 richieste KV |
| 10 | [`kv::verify`](../../rust/volta-pcs/src/c71_matrix/gemma/bytes/kv.rs) sulle richieste del passo 9 | Segmenti presi da `S.accepted`, poi C_A corrente. Un target per vecchia A in BOld, target corrente derivato in BA |
| 11 | [`o.verify_lookup`](../../rust/volta-pcs/src/c71_matrix/gemma/output.rs), softcap atteso | `o.forms` e X/Y/M originali in BA; head RNE era già nel passo 5 |
| 12 | [`m.verify`](../../rust/volta-pcs/src/c71_matrix/gemma/softmax.rs), EXP30 atteso | `m.forms`: massimo, X/Y/M lookup, byte E/Z/Pi del rapporto in BA |
| 13 | [`range::verify`](../../rust/volta-pcs/src/c71_matrix/range.rs) per W flat D35/symmetric(32767), poi A corrente flat D34/Byte | Due forme/target originali range e padding per ciascuna, in BW e BA rispettivamente |
| 14 | [`linear::verify`](../../rust/volta-pcs/src/c71_matrix/linear.rs) su BW/C_W, poi BOld/C_Aj in ordine crescente j, infine BA/C_A | Un'unica PCS per ciascuna sorgente; tutte con righe fresche del tentativo corrente; nessun target rimane aperto |

Per argmax si usa `o.output/o.slack`, 50 righe e vocabolario pinned; la
forma è compilata sui byte originali come nel caso output nativo. Le
ricette delle richieste RNE sono quelle comuni, non shift del certificato.
Nomi `rms`, `gelu`, `gate_up`, `rope` denotano gli oggetti annidati nella
stessa sorgente finale, non copie con layout precedenti all'estensione.

Il conteggio è **775 target W**, **4.446 target A corrente**, **uno per
ciascuna vecchia A**. BA si riconcilia con la tabella del
[compilatore](../c7.1-history/c7.1-gemma31b-design.md#b12-profilo-numerico-comune-ricette-derivate-dai-produttori):
1545+1264+410+964+3+3+2+240+1+3+5+4+2=4446. BW ha
773+2=775. I range precedenti si ereditano esclusivamente dal registro;
le aperture precedenti non ereditano tag o righe. W ha tre aperture,
A0/A1/A2 hanno 3/2/1 aperture. Non compare una PCS per token o una nuova
sorgente separata per tracce, bit, probabilità, logits o KV.

## 4. Soundness: dalle aperture alla transizione accettata

**Evento globale.** Riutilizzare l'unico esperimento di cattivi prefissi
B12, con Q*=2^74 globale, i bad event Merkle (collisione e preimage
differito), bootstrap/seal, PCS/RS, range, MAC e tutti i blocchi GKR/RNE/
lookup/forme già sommati in `ordinary_KV_output_and_EXP30_composition`.
La nuova schedule non altera quei polinomi o aggiunge sfide; fissa i loro
prefissi in un unico transcript. Query a candidati scartati e prefissi
prima di una pubblicazione rimangono inclusi. I digest di profilo/stato
sono nel medesimo oracolo/query census; le identità attese non si leggono
da una prova. Non si assume indipendenza dopo aver condizionato sul futuro
successo né si moltiplica di nuovo Q* per tre tentativi.

La riduzione costruisce la mappa Merkle alla prima dichiarazione di C_W
con le sole informazioni al suo prefisso, usando il decoder unique-radius
B12 una volta. Ripete per ciascuna A effettivamente dichiarata, al più tre.
Queste mappe non vengono ricalcolate dopo le sfide o scegliendo un futuro
predecessore. Sulle root prive di messaggio vicino si usa la convenzione
del lemma PCS: un'accettazione utile richiede il relativo bad event.
Fuori dall'unione degli eventi, tutte le aperture accettate sono forme
dei medesimi quattro messaggi; il range rende W i16 simmetrico e A byte,
con il suffisso flat nullo. Nei rettangoli, il padding interno prescritto
è controllato dai rispettivi produttori/forme, non dal solo suffisso flat.

**Lemma di cucitura dei valori.** A quel punto il MAC di un input P0,
il MAC dello stesso output passato alla RNE e il target byte della PCS
denotano un unico valore. La verifica RNE non termina con una nuova
autenticazione libera: la forma dei byte raw è l'originale restituito.
Per ogni altra famiglia vale la stessa identità del §3. In particolare:

- una coorte matrice falsa ha una discrepanza nonzero su C/X/W fissati;
  le sonde e la riduzione P0 già contate la escludono; i 773 endpoint
  W proiettano sempre i 772 tensori fisici della W installata;
- RMS collega P=XW, S=sum X² e Y; le X locali V e gli alias globali
  pre-norm K/V conservano l'ID originale. Non basta dimostrare S/Y fra loro;
- le 410 richieste RNE originali e le 482 sonde sono disgiunte e coprono
  i 892 produttori RNE; RMS/GELU/EXP30/softcap completano tutti i 1.434
  owner di attivazioni. L'ulteriore lookup embedding appartiene a W;
- QK/PV usano quotient-GQA e gli eager rectangle dichiarati; Pi è la stessa
  sorgente in maschera causale, EXP30 e PV. Il MAC M di PV è scaricato
  verso Pi, non conservato come testimone libero;
- massimo/differenza/lookup EXP30/somma/rapporto esatto determinano ogni
  Pi ammessa; le posizioni future e padded sono nulle. Tutti gli ausiliari
  appartengono alla stessa A; gli istogrammi precedono alpha;
- somme, scale, head, softcap e argmax chiudono sui loro byte originali.
  Tutti i valori semantici sono nel range del loro produttore, senza
  trasformare byte-validity in una prova di RNE o di i16 simmetrico.

Il passaggio dal campo agli interi usa gli envelope già provati: prodotti
i16, accumuli P0, QK/PV e RoPE hanno differenze assolute <p; l'affine ha
`|R-aX-bY|≤2^47+2^46<p`. Le routine RNE/RMS/ratio verificano i predicati
interi con i byte originali, u128 e profili pubblici limitati. Per EXP30
`2^30≤Z≤450*2^30<2^39`. Non si accetta un'identità soltanto modulo p
come identità intera fuori da questi inviluppi.

**Induzione su layer, token e risposte.** Nel primo tentativo lo storico
è vuoto. Fissato W, embedding identifica il valore iniziale per ogni token
pubblico; le identità appena provate determinano i successori nell'ordine
del DAG. A una query t la maschera limita K/V a posizioni ≤O+t. All'interno
di un layer K/V di quelle posizioni sono calcolati da layer precedenti:
non c'è un ciclo attraverso il token futuro. L'head usa righe 99..148 e
argmax le collega esattamente a token 100..149. Induzione su queste 50
decisioni dà i token della generazione sequenziale, anche se il certificato
li presenta insieme. Le sorgenti di 150 righe certificano anche K/V
del token 149: la promozione non lascia l'ultimo token pendente.

Supporre ora vere le prime j risposte accettate. Al passo j il registro
fornisce proprio quelle A e i loro layout, mai una ricevuta importata.
Il router KV dimostra, per ciascun endpoint originale, la forma

```text
L(KV)[r] = sum_{i=0..j} sum_{t=0..149,c}
            eq(r_key,150*i+t) * eq(r_channel,c) * tail(A_i)[t,c].
```

I blocchi sono allineati nei domini locale e globale. Ogni vecchia PCS
lega l'aggregato fresco alla stessa A_i già decodificata; il target
corrente è la differenza dall'aggregato degli **originali** QK/PV.
Il lemma di batching già contato esclude una compensazione falsa fra
endpoint. La cucitura quindi usa esattamente il KV prodotto in precedenza
con W, più la coda corrente. L'induzione DAG dà la risposta j e la sua
coda sul medesimo W. Solo adesso il passo 5 promuove A_j.

Un errore a qualsiasi altezza lascia invariato il registro e termina.
Replay, fork, ACK, certificati parziali e una sola PCS valida non possono
creare un'ipotesi induttiva. Perciò il primo falso stato accettato implica
uno degli eventi già limitati: **Pr[false acceptance]≤ε_S**, senza un
termine aggiuntivo per un'induzione deterministica o una promessa di
«integrazione corretta».

## 5. Simulatore congiunto e NoPeek

Sostituire il bootstrap reale con il funzionale B11 con la perdita
ε_boot già contata. Il simulatore esegue V* una volta, senza rewind,
conservando le sue query e il suo stato. Installa una W fittizia unica
di 772 tensori zero con il prover PCS ordinario. Su una richiesta ottiene
dal funzionale dell'inferenza gli output pubblici o `Stop`; in quest'ultimo
caso termina alla stessa boundary prima della prova. Non cerca W.

Per ogni risposta completa prepara lo snapshot fittizio del
[lemma zero-W](../c7.1-history/c7.1-gemma31b-design.md#b12-output-canonico-lm_head-softcap-e-decisioni-nella-stessa-a):
hidden/raw/KV zero, D=0 ed E=2^30 su tutte le celle lookup, comprese
quelle vietate; su ogni query viva Z=k*2^30 e Pi=RNE(2^14/k),
k=O+t+1. Z è zero sulle query padded; Pi è zero sulle posizioni
vietate/padded. Le maschere nella somma Z escludono gli E vietati.
Istogrammi, differenze e byte biased sono quelli veri di questo snapshot;
A fittizia **non è il vettore zero**. Qualunque profilo valido della
famiglia ammette tale trace: RMS ha epsilon positivo, GELU/softcap(0)=0,
RNE(0)=0 e Pi entra nel range simmetrico fino a k=450.

Il simulatore esegue i prover ordinari nell'ordine del §3 usando le righe
ideali ricostruite dalle chiavi corrotte e valori uniformi. Per il solo
target pubblico argmax, con valore effettivo F sullo snapshot fittizio
e bias/target pubblico b, usa `Auth(F,Delta*(b-F))`: la key del verifier
rimane `Delta*b`. Con slack unsigned zero F=0, anche se il token ideale
non è quello scelto dal modello zero. È un'operazione del simulatore DV,
non del prover reale. Non corregge il target del verifier, non cambia
la root fra operatori e non programma FS.

**Disciplina NoPeek scaricata.** L'algoritmo del §2 ha quattro classi di
plaintext autenticati:

| Classe | Dati letti prima della prossima riga |
|---|---|
| Probe, endpoint e aggregati KV | Snapshot W/A immutabili, forme e sfide già nel transcript |
| Coefficienti sumcheck/GKR, funzioni byte e split | Tabelle/celle deterministiche di quegli snapshot e sfide precedenti; dimensioni/alias pubblici |
| Istogrammi e prodotti intermedi | Snapshot e operandi già fissati; istogrammi prima di alpha, prodotti prima della propria mask |
| Chiusura PCS | Coin PCS separati, target originale, replay pubblico; shift MAC proprio e monouso |

La lista è esaustiva dei kernel della schedule. Nessuna classe legge una
correlazione ancora inutilizzata per decidere il proprio valore, shape,
alias o ramo. I lookup respingono i poli dell'**intera tabella pubblica**;
su un witness onesto questo include ogni possibile polo privato. RMS,
overflow e istogrammi sono preparati prima di A; i successivi controlli
su dati privati sono equazioni MAC, non emissioni diagnostiche. Un input
pubblico malformato, un polo pubblico, un sampler o un arresto scelto da
V* sono predicati della vista; i fallimenti dei sampler privati stanno
negli eventi statistici già contati.

**Una sola traslazione della vista.** Passare ai coin uniformi e alle
label Merkle ideali come nella prova claimless B12. Fissare una vista
pubblica completa, inclusi tutti i prefissi FS e la casualità di V*.
Per ognuna delle quattro sorgenti si usa un unico inverso destro canonico
del sistema RS sull'**unione** dei punti esposti nell'intero run. W/A0
hanno ≤1536 punti, A1 ≤1024, A2 ≤512, coperti dai 1536 pad. Le differenze
fra snapshot reali e fittizi determinano così una sola traslazione dei
pad iniziali per sorgente, non una sostituzione indipendente a ogni proof.

Per un MAC con key fissata `k=m+Delta*x`, la correzione d=v-u si conserva
ponendo `du=dv` e `dm=-Delta*du`. NoPeek rende queste traslazioni
triangolari nell'ordine di consumo. Gli alias condivisi hanno **un'unica
dv**. Le operazioni lineari, i tag dei residui veri e il batch QuickSilver
si conservano mediante la propria maschera fresca, con i segni nativi.
Per i target pubblici si conserva k e si trasla il tag come sopra.

Ogni PCS conserva coefficienti visibili, OOD e righe con le traslazioni
di rango pieno della prova B12. Al terminale, per il suo scalare z,
covettore `A*z+B`, blind g e shift eta:

```text
dg = -gamma*dh,       deta = gamma*A*dz.
```

Una key condivisa da due componenti usa la stessa dz; ogni PCS ha il
proprio eta e può applicare la formula. Un aggregato KV di una vecchia
A usa il valore di quella medesima A, con una riga MAC nuova. Non è
necessaria indipendenza dei witness W/A o degli endpoint. Le coordinate
casuali delle diverse PCS e i 39 stream sono disgiunti; quelle iniziali
di una stessa sorgente sono invece traslate una sola volta.

Questa mappa ha inversa cambiando segno alle differenze degli snapshot
e applicando le stesse equazioni nell'ordine inverso. Conserva tutta la
vista, incluse correzioni, tag, salti, aperture, roots, record finali e
quindi ricevute. I challenge sono quelli dei **veri prefissi FS**; non
si assume che siano uniformi dopo aver fissato la vista. La sola
eccezione al passo OOD resta rho=0, già addebitata come Q*/q. Nessuna
divisione per Delta, gamma o il coefficiente A viene aggiunta.

La scelta adattiva della richiesta successiva è una funzione della vista
preservata. Le due esecuzioni scelgono quindi lo stesso prompt, lo stesso
predecessore e lo stesso punto di terminazione; per l'induzione sulle
tre risposte gli snapshot fittizi mantengono W=0 e le proprie code zero.
La proiezione su un prefisso interrotto conserva l'uguaglianza di legge.
Ritornando da label/coin ideali alla PCS ordinaria fittizia si ottiene

```text
ε_Z = ε_boot + 2 ε_joint_Merkle_hiding_and_coins
             + Q*/q + 2 ε_joint_private_sampler.
```

È la stessa foresta congiunta da 526 alberi, 39 stream e sei aperture A
già contata. Non si sommano nuove ZK per ogni operatore, non si azzera
l'hiding delle root e non si deduce ZK dalla sola accettazione del dummy.

## 6. Risorse, riuso formale e confine runtime

`complete_fixed_run_composition` conserva le somme razionali precedenti
e aggiunge al riduttore un envelope esplicito per assemblaggio, stato e
preparazione del dummy: **2^80 operazioni u64, 2^70 parole, 2^42 eventi
RO onesti**. Il massimo totale rimane <T121/M93 e le query <Q*=2^74.
Questo è un upper analitico per entrambi i ruoli, non una misura.

Il preparatore denso valuta al più tre grafi con ≤450 posizioni, 60 layer,
larghezza ≤21504 e vocabolario 262144. Anche l'enumerazione delle matrici
rettangolari e dei raw, con ≤2^12 operazioni u64 per operazione di campo,
resta sotto 2^70; gli snapshot W e tre A richiedono <2^38 parole.
Il costo maggiore, già ereditato, è quello di decoder, PCS e replay
GKR densi. Per la composizione, anche visitare ≤2^19 cubi su ciascun dominio
≤2^35, per nove aperture e con lo stesso fattore 2^12, usa <2^70
operazioni. Lettura/hashing dei parametri pubblici e dei record, dispatch,
registry e propagazione di key/forme stanno sotto l'ulteriore envelope.
I cap pubblici dei compilatori sono applicati prima di quelle allocazioni.
Non si decodifica ogni candidato FS: quattro decoder totali, mentre il
trie/tape delle query candidate rimane nel costo globale già dimostrato.

Le correlazioni sono **11.466.948 righe base** per i tre tentativi,
entro 16.777.206 iniziali. La composizione non aggiunge MAC, PCS, stream,
sfide o termini d'errore: aggiunge confronti pubblici e una regola di
promozione. La preparazione del parametro numerico da cui si sceglie Γ
e la sua qualità come modello sono questioni distinte; leggere le tabelle
di Γ e verificare che siano quelle attese non è costo zero nel protocollo.

| Fatto usato | Evidenza e limite del trasferimento |
|---|---|
| Operazioni lineari preservano MAC originali | [`Mac.Valid.add/smul/sum`, `ofPublic_valid`](../../lean/VoltaZk/Mac.lean); applicati ai segni nativi k=m+Delta*x |
| Correzioni e residui hanno simulazione sui prefissi | [`BlindSumcheck.realView_map_publicView`, `bsc_zeroBatch_perfect_zk`](../../lean/VoltaZk/BlindSumcheck.lean), batch prodotti/range B12 e [G2 §3.1](../c7.1-history/c7.1-committed-mac-opening.md#31-simulatore-ideale-fs-nessuna-programmazione-delloracolo); il §5 scarica shape, NoPeek e alias del caller |
| KV è append dei tail accettati | [`prefix_stability`, `accepted_append_tails_induction`](../../lean/VoltaZk/C7StatefulAlfc.lean); il §4 dimostra la premessa di validità delle code per questa relazione |
| Unione eterogenea con Q globale | [`c7_gemma_gkr_heterogeneous_qfs_union_bound_once`](../../lean/VoltaZk/C7GemmaGKR.lean); i gradi sono quelli B12 ricontati, non il vecchio numeratore congelato |
| Root → stesso messaggio → endpoint | Analisi RS/MCA/Merkle e invariante scalare nativo B12; nessun lemma Lean storico è presentato come dimostrazione del fork PCS |

## Estensione Seed6 e obblighi residui

Il trust model del percorso efficiente include la premessa autorizzata:

```text
Adv_EA-LPN-SL-reg*(675,70778880,353894400,11,Fp;
                  T=2^121,M=2^93,one-leakage) <= 2^-80.
```

Non è un risultato empirico LPN né una conseguenza dell'ipotesi AES.
Seed6 usa Fp6→Fp3, due seed a ruoli opposti, guard dei cammini, cGGM
con oracoli separati per nodo, coin con commitment/apertura e F_EQ.
Le identità implementate e la macchina monouso sono in
[specs](specs.md#correlazioni-seed6); il [conto condizionale](../c7.1-history/construction-screen.md#seed-fp6-compressione-a-95-bit-nel-singolo-setup)
rimane distinto dai bound completi dei §§1–6.

Il guard impone `gamma*(gamma-beta)=0` sui MAC originali prima delle
correzioni cGGM. Con beta nonzero estrae un cammino binario; il ramo beta
zero ha una simulazione separata. Il bound ideale è `(t*h+1)/|Fp3|`.
Il costruttore onesto campiona beta in Fp* senza abort osservabile.
Il cGGM usa `left=H_D(x), right=x-H_D(x)` dopo uno split iniziale
indipendente. La riduzione condizionale contro il receiver paga
`Q_ROM/|Fp3|` per le query anticipate ai nodi nascosti.

F_EQ autentica gli input con due chiavi fissate prima delle correzioni
e apre solo share del prodotto `(Delta0+Delta1)*(wbar-vbar)`.
Una seconda coin precede commitment e aperture ordinate per ruolo.
Con chiavi B11 nonzero, una share malevola fissata prima dell'apertura
accetta un mismatch con probabilità ≤`1/(|Fp3|-1)`; la distanza statistica
fra viste di rifiuto è ≤`1/(|Fp3|-2)`, con abort e burn. Il seed EA
derivato dalle aperture accettate richiede blind onesto fresco, binding
dei commitment e nessun retry. L'analisi locale aggiunge un termine
<2^-108; non costituisce una riduzione globale già conclusa.

Restano da chiudere la composizione malevola di bootstrap/guard/cGGM/
split/F_EQ/EA, il conto completo delle risorse della riduzione, e la
corrispondenza dei codec e dei prefissi nativi all'esperimento matematico.
La sostituzione reale→ideale del §5 riguarda ancora B11/B12.
Canale autenticato e journal durevole non riportabile indietro sono
premesse esterne; i socketpair dei test non le realizzano in distribuito.
Il runner CPU trasporta ora anche Γ/tabelle, installazione e richieste
sui socketpair e ricompila Γ dal lato V. I nuovi record pubblici e i
contatori locali non certificano le tabelle, non autenticano TCP e non
chiudono il raffinamento della composizione Seed6. Le misure di fase sono
diagnostici locali fuori dal transcript; non contengono valori privati.
Nessun bound 82,93/91,02 viene attribuito alla composizione Seed6 completa.

### Obblighi del runner implementato

Le credenziali provider, la durata della campagna e lo spegnimento sono
esterni al protocollo; la procedura corrente è nel
[runbook](runpod-tests.md#autorizzazione-e-limiti). Una campagna autorizzata
comprende più trial indipendenti nel proprio ambito: ciascuno riparte da
O=0 con nuove correlazioni e journal. Ciò non riprende un
esperimento crittografico terminato. Il riuso di input o binari non
autorizza riuso di correlazioni, journal o KV terminale.
Le ottimizzazioni della schedule conservano distribuzioni, NoPeek,
endpoint MAC originali e ordine del transcript; i numeri di scansioni
dell'implementazione corrente non sono parametri di sicurezza.

Il [prover CPU](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_prove.rs)
e il [registro](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_state.rs)
collegano schedule, verifica e promozione dopo journal durevoli. Il runner
misto conserva gli stessi messaggi, polinomi e MAC originali. La presenza
del codice e i test finiti non sono un lemma Lean di raffinamento o una
prova della composizione Seed6. Γ reale è ammesso sul workload pinned; il suo riuso richiede identità e
impatto compatibili. Restano da verificare pipeline canonica positiva,
getter su tutti gli operatori/alias e copertura dei MAC originali nei
certificati prodotti.

Scanner e reader emettono soltanto valori dello snapshot immutabile,
senza monete PCS o correlazioni. Lo scanner richiede una sola emissione
per coefficiente; il conteggio totale non dimostra unicità degli indici.
Padding, pad privati, sali e ordine dei resti sono preservati. Le riduzioni
S1 usano Eq sul prefisso già fissato e sull'indice originale, sommando i
contributi folded senza creare nuove sorgenti. Singleton, coset, OOD e
retention restano distinti; errori impediscono l'installazione di stato
parziale. Il batching del replay condivide letture W, non arrotondamenti,
polinomi o nuove autenticazioni. La cache Q termina al secondo fold e
non riusa monete o correlazioni.

Il gather range permuta solo indirizzi pubblici, preservando MSB e bit
del sottoalbero. Il reader restituisce i byte originali nello stesso
ordine dello scanner, con il bias previsto: una root uguale non dimostra
questa proprietà. L'istogramma originale è fissato prima delle correlazioni
e autenticato nel range. Le contrazioni H operano sul tail pubblico e i
fold usano le sfide già emesse, secondo la fraction tree; nessuna finestra
diventa un nuovo commitment o MAC. W signed usa gli stessi originali,
con suffisso zero nel medesimo dominio. I dettagli sono nelle
[specifiche](specs.md#preparazione-e-prova-a-memoria-limitata).

Il kernel denso conserva il prodotto intero con split signed, quattro
MMA INT8 e correzioni esatte, accumuli bounded e raw i64; RNE, Norm u128,
lookup, EXP30, RoPE e argmax mantengono la semantica selezionata e rifiutano
overflow. I test host e la parità CUDA ridotta non provano il raffinamento
concorrente generale dei kernel o il forward Gemma completo. Il codec
byte ammette −32768 per lo slack argmax biased-u16, senza ammetterlo come
input aritmetico ordinario.

L'owner valida ABI, identità del runtime, handle, span, shape e alias;
handle coincidenti di librerie o contesti distinti non autorizzano consumo.
Un solo lock governa l'owner durante il range; il reader residente non
riacquisisce quel lock e non riceve transcript o MAC. Output e istogrammi
restano pending fino a copertura completa, fence e flag validi. W parziale
o riscritta, errori asincroni, cleanup/free fallita o uscita senza
finalizzazione sono terminali, senza fallback o nuova arena. La libreria
è codice locale fidato, non un oggetto fornito dal certificato.

W numerica e PCS condividono la stessa Arc immutabile installata; quel
collegamento di implementazione resta da raffinare al binding matematico.
KV usa una sola capacità per 450 token; viste storiche non leggono celle
future, anche già inizializzate. Il registro determina il predecessore,
non il costruttore della vista. Append fuori ordine o fork sono rifiutati
prima delle copie. I token argmax non sono accettati prima dell'intera
prova: la promozione segue verifica, completamento legato al certificato
e journal durevoli di entrambi i ruoli, mai un ACK generico.

La rigenerazione assume determinismo dei kernel corretti su W/tabelle
sigillati, token fissati e prefissi KV originali. Si controllano token e
copertura, ma non un digest privato di tutta A confrontato a ogni replay.
Il replay per producer completo ricostruisce uno snapshot già fissato;
la generazione iniziale resta causale. Questo è un obbligo esplicito di
implementazione, non una conseguenza della sola parità finita.

I consumer CPU possono leggere righe/finestre private bounded mediante
`c71_original_read`, dopo controllo del prefisso e fence. Sono staging
del prover, non messaggi al verificatore. Tutte le copie e capacità
trattenute entrano nel conto delle risorse. Il runner ferma l'owner anche
su errore della prova CPU; nessuna promozione riattiva uno stato fermato.

Il [checkpoint H100 del 4 ottobre](../../benchmarks/results/c71-h100-diagnostic-checkpoint-2026-10-04-e3f08e939eef.json)
verifica parità sintetica e percorso ridotto sui MAC originali. Il
[record del 7 ottobre](../../benchmarks/results/c71-gamma-admission-2026-10-07-868a3e8.json)
chiude tutti i cinque controlli di ammissione Γ sui pesi reali: due replay
identici e confronto C11/Python indipendente completo, incluso KV finale.
È una verifica finita delle identità e del workload pinned; non dimostra
un raffinamento generale Rust/CUDA, la composizione Seed6 o i certificati
canonici. Accelerare il pilot floating, da solo, resta inizializzazione
offline; conservare l'indipendenza del driver numerico intero.

Avanzamento e tempi sono telemetria locale di laboratorio, fuori dal
transcript e senza nuovi messaggi al verificatore. I report pubblici
contengono solo la selezione revisionata di contatori/shape e tempi;
non espongono W/A/KV, intermedi o ragioni private di arresto. Tempi e
accessi fisici restano fuori dal claim ZK matematico. Le ipotesi B12,
EA-LPN-SL-reg* e di raffinamento aperte non sono scaricate da queste misure.

Il [seguito locale](../c7.1-history/local-followup-2026-10-10.md) conserva
questo confine: fill dello zero pubblico con le stesse guardie/flag/fence,
traccia owner solo diagnostica con schema pubblico revisionato e file
privato bounded, senza handle/puntatori/monete/valori W/A/KV. Errori di
logging fermano l'owner ma non omettono cleanup o debito di free fallite.
Clock anchor e snapshot di capacità non sono ricevute o witness importabili.
Le parità RMS/predicate/packed/supporto ridotte e gli upper analitici non
concedono qualità Γ, nuovo budget completo o raffinamento Rust/CUDA.

Il buffering mantiene lo stream privato B12, rejection sampling e cap
monouso 2^40. Seek/snapshot usano il cursore logico, non quello fisico
dopo prefetch; il replay strided non copia buffer o crea nuove monete.
Le fixture confrontano confini/cap, sali/root/aperture e transcript sui
MAC originali; non ne segue un nuovo lemma Lean di raffinamento. Il
JSONL privato durevole non abilita resume, importazione di ricevute o
riuso di correlazioni; errori e timeout mantengono terminalità.

La [parità locale del primo checkpoint](../../benchmarks/results/c71-crypto-preparation-local-2026-10-08-04ab8ed1c4ce.json)
copre questi invarianti e un positivo Seed6/AES ridotto; le premesse
aperte di composizione e raffinamento rimangono quelle dichiarate sopra.

### Riduzione dei temporanei e confine del claim

Le ottimizzazioni conservano enunciato e distribuzione crittografica.
Le [evidenze e decisioni](design.md#evidenze-e-decisioni) distinguono
componenti, integrazioni e risultati completi; i record conservano anche
failure e timeout. Nessuna parità finita o misura locale scarica le
premesse B12, Seed6, determinismo o raffinamento CUDA dichiarate sopra.

**Hash e accumuli W.** La foglia incrementale conserva dominio B12,
byte little-endian dei 128 valori e quattro sali, counter/flag dei chunk
e root BLAKE3. CV e frontier incompleti non sono digest pubblicabili:
ordine/copertura dei blocchi, bande e gruppi, fence e flag precedono la
pubblicazione. Il merge strided ricompone la stessa root naturale e il
Tree mantiene Arc/layout W, pad, sali e getter originali. La somma signed
<2^87 e la riduzione Goldilocks sono identità controllate con modulo i128
indipendente; non cambiano basi Fp3 e non hanno un lemma Lean di
raffinamento del kernel o dello scheduling. Tensor limb16 è selezionato
per W dopo la [parità e il confronto H100](../c7.1-history/h100-components-2026-10-09.md);
il confronto bitwise sul common owner non autentica nuovi valori e non
espone campi al verificatore. Le candidate QK/PV MMA restano non selezionate.

**Producer A e copertura.** Il sink residente consuma gli stessi byte
biased degli originali numerici; l'ordine fisico delle emissioni e le
somme modulari esatte mantengono i coefficienti. Producer e preparatore
ricevono solo buffer/layout/sink, senza monete PCS, transcript o
correlazioni. Accumuli/conteggi restano pending fino a copertura, pad,
FFT e flag completi. Il C ABI controlla span, stato e conteggio; unicità
e partizione degli indici sono precondizioni dello scanner Rust fidato,
con negativi di righe duplicate/omesse. L'istogramma è fuso nel primo
replay, senza MAC o scansioni aggiuntivi. Il Tree conserva cut, ordine,
root/cache ed aperture; la promozione non impedisce replay storico.

**Monete private.** Buffer sequenziale, batch strided e sampler GPU
conservano dominio originale incluso NUL, stream LE, rejection, seek,
clone MMCS e cap 2^40. Prescan parte dal cursore logico e avanza l'host
una sola volta dopo successo; il prefetch non altera il cursore pubblico
del sampler. La capability owner-bound è opaca e non clonabile, senza
lettura/upload/rilascio generico. Seed, token e puntatori privati non
arrivano ai producer o alla telemetria. Replay e hash condividono il flag
sticky; consumo e cursori finali devono coincidere col prescan, prima
del ritiro privato e della lettura digest. La gerarchia CUDA prescan
rimane da verificare su hardware. PCG reale AES e correlazioni monouso
non sono sostituiti dal sampler di sali PCS.

**Aperture, FFT e closure.** Il raggruppamento valuta gli stessi punti;
aperture contigue conservano ordine, duplicati e path potati. Divisione
per piccoli divisori monici e FFT naturali diretta/inversa mantengono
coefficienti ed endpoint originali. La normalizzazione inversa è una
sola moltiplicazione per 1/N; twiddle sono legati a lunghezza/orientamento,
con buffer distinti e guard owner/span/stato. Le primitive FFT base
Goldilocks non reinterpretano PCS v³=v+1 come MAC u³=2: un caller di
estensione deve conservare separatamente le tre componenti originali.
La lettura bounded di word base nega le fasi sali private. Il
[checkpoint FFT](../c7.1-history/crypto-transform-2026-10-09.md) valida
la primitiva, senza validare query A o S1 residenti.

Il successivo [checkpoint query A](../c7.1-history/crypto-query-2026-10-09.md)
collega il reader residente conservando gli stessi intervalli originali,
ordine, duplicati, pad e endpoint MAC. Il reader numerico riceve soltanto
runtime e intervallo pubblico: spettri query e pad PCS restano nel
consumer. Valori originali non sono scaricati; solo la matrice finale
passa al Tree prima dell'autenticazione Merkle. Errori, owner/span/tipo
alterati o buffer pending sono terminali, senza reader/getter sostitutivo.
La catena ridotta uncached conserva wire, FS/RNG e MAC originali con due
verificatori; non dimostra parità CUDA o ammissione fisica. Extension/S1
e caller lineare restano CPU al source di quel checkpoint.

Il successivo [checkpoint lineare](../c7.1-history/crypto-linear-2026-10-09.md)
valida owner/caller sugli originali, usando MAC u³=2 e marshalling
canonico distinto dalla PCS. Packet e token sono owner-bound; begin
completa gli upload, finish controlla flag/campi e ritiro prima di
autenticare il round. Scanner A e mapping W restano quelli originali;
sfide e covettori rimangono nel consumer. Errori di copertura, producer,
symbol, copy/fence/free non consumano le tre correlazioni di un round
incompleto e fermano l'owner, senza getter fallback. La prova D10 signed
W conserva full wire/FS/punto/MAC; i codec A sono verificati separatamente.
Non ne segue un lemma Lean di raffinamento, parità CUDA o completamento
del profilo canonico. Extension/S1 restava CPU a quel checkpoint;
le premesse delle viste residenti e del loro lifetime restano esplicite
anche nella successiva integrazione.

La [correzione dei lifetime e il Merkle extension preparatorio](../c7.1-history/crypto-retirement-short-merkle-2026-10-09.md)
non cambiano FS, MAC, correlazioni o byte del protocollo. Batch/prove owned
sono rilasciati dopo l'ultimo consumo; il timeout composto non dà parità.
Le foglie extension conservano base PCS, limb/byte order, sali e blocco
finale BLAKE3. L'helper paired era preparatorio a quella sorgente storica;
pubblica R nodi soltanto dopo tutte le 2R foglie.

Le [query iniziali W](../c7.1-history/crypto-local-convergence-2026-10-09.md)
leggono lo stesso packed sigillato con controllo del prefisso vivo prima
dell'indirizzo; pad, ordine/duplicati ed endpoint restano originali.
Il nuovo simbolo è obbligatorio e gli errori sono terminali. Retirement
prima dell'hash A e capacità fissa Writer conservano byte, sali, root,
FS e MAC. I sottoconti RMS legati al Γ ammesso non sono una prova di
prestazioni o di fattibilità congiunta; le assunzioni formali restano aperte.

**S1 e Query E.** Il
[checkpoint residente](../c7.1-history/crypto-residual-query-2026-10-09.md)
collega il consumer PCS allo stesso `native_original` del modello.
La base PCS v³=v+1 usa marshalling tipizzato distinto da MAC u³=2;
ogni lettura originale o retained produce tutte le tre componenti nel
medesimo passaggio. EQ, pad e sfide restano nel consumer: il producer
riceve soltanto il sink ed indici pubblici, senza nuove informazioni
PCS o correlazioni. Il C ABI conserva span/count; unicità originale A
è responsabilità del `NativeSource` Rust fidato, tramite copertura esatta
per riga e partizione dyadic dei byte. Non dedurre unicità dal solo count
di una chiamata C autonoma. La verifica del piano pinned e la rimozione
del controllo C ridondante sono documentate nel checkpoint storico.
Il contratto originario dello scanner non è indebolito.

Plane e ring privati sono sigillati soltanto dopo flag/fence validi;
generazione e ordinalità c0/c1/c2 impediscono sostituzioni o scambi di
limb. La retention A segue l'apertura e il rilascio dell'oracolo iniziale;
promozione e fold non modificano un predecessore ancora apribile. W
continua a leggere gli originali packed. Query E mantiene capability,
ordine discendente, limb, grado ed ultimo handle della lineage; vieta
letture e mutazioni generiche durante la transazione. Solo valutazioni
finali canoniche sono pubblicate dopo il ritiro dei temporanei, poi
autenticate dal Tree e chiuse sui MAC originali. Non è introdotto un
nuovo endpoint autenticato o una scansione originale A per limb.

Le catene WHIR ridotte A/W conservano full wire, FS/RNG e MAC originali
ideali fissati; in produzione restano PCG reale AES e correlazioni
monouso originali. Queste parità non dimostrano il profilo canonico,
la correttezza CUDA o i target. Raffinamento dei kernel, determinismo
del replay, composizione Seed6 e sufficienza della riserva fisica restano
le assunzioni dichiarate nei §§1–6 e nel design.

S1 si ridimensiona soltanto dopo consumo/rilascio del predecessore e
registrazione del successore; nessun oracolo ancora apribile è modificato.
La closure lineare scansiona originali una volta per round, con EQ/sfide
nel consumer e solo sink nel producer. Le tre correlazioni del round
si consumano dopo scansione riuscita; riserva/burn 3D+2, wire, endpoint,
MAC e transcript rimangono invariati. Range/count non provano unicità.
Le fixture composte usano MAC ideal fissati e cache di riferimento da
16 MiB solo nel test; produzione mantiene PCG AES e getter senza cache.
Timeout uncached W/A e CPU lookup/GKR/WHIR non sono pass.

**Causalità attention.** La candidata precedente leggeva KV fino al
massimo causale del tile, annullando gli output futuri: viola il contratto
per-riga del §6. Il default scalare era invariato. La
[correzione distinta](../../benchmarks/results/c71-attention-causal-local-2026-10-09-29a257b4476b.json)
usa MMA sul prefisso comune e bordo scalare per output; guard di lettura
coprono anche future KV/Pi già inizializzate. Il record del finding
rimane immutabile. La candidata resta non selezionata e la sola parità
numerica non dimostra causalità o scheduling GPU.

**Memoria e terminalità.** Entrambi i ruoli, capacità mantenute e
old+new durante realloc sono nel medesimo contatore; soltanto il payload
W packed è escluso. Errori di identità/geometria/copertura, launch,
fence, budget e cleanup sono terminali: niente promozione, spill,
seconda arena o fallback. La riserva fisica di 256 MiB è un'ipotesi da
verificare sulla H100, non un lemma o una misura. Bound di allocazione,
subtotal analitici e test ridotti non provano completamento canonico,
picco fisico o prestazioni. I lemmi congelati non cambiano.

Il [preflight delle forme originali](../c7.1-history/crypto-capacity-close-2026-10-09.md) ripete prima di W e delle
root A storiche gli stessi controlli pubblici del bind. Non legge valori,
tag o chiavi, non emette record FS e non consuma correlazioni. Un rifiuto
anticipato resta terminale nella riserva già bruciata. Compattazione dei
vettori KV e trasferimento delle forme W conservano ordine, coefficienti,
endpoint originali e byte; il test lineare completo confronta wire/FS/MAC.
I bound tipati di memoria restano condizionati al manifest e distinti dal
picco fisico: non scaricano le premesse formali o Seed6 sopra dichiarate.

**Replay e preflight RMS.** Il
[checkpoint RMS](../c7.1-history/crypto-rms-close-2026-10-09.md) valuta
gli stessi DAG Booleani con 64 lane CPU, preservando l'ordine di ogni
frame/cella, alias, padding e copia dei wire. La selezione riguarda solo
`pattern_prefix.is_none() && programs.len()>1`; statistic e pattern
singoli mantengono il percorso precedente. Il primo round esatto
valuta lo stesso polinomio dei coefficienti, senza sfide anticipate,
monete nuove o modifiche ai MAC. La fixture GKR completa confronta
wire, transcript/RNG, consumo esatto ed endpoint sui MAC originali;
il suo esito finale resta quello del [record](../../benchmarks/results/c71-crypto-rms-local-2026-10-09-abd2de09efb4.json).
È una fixture senza PCS: non sostituisce la composizione PCS già
verificata né concede nuovo credito alla catena reale che va in timeout.
La cache di preflight contiene chiavi pubbliche confrontate esattamente
e width derivate dal compilatore; ripete i controlli di contesto/layout,
shape, Gamma e tentativo, senza riusare correlazioni o transcript.
Queste parità locali non raffinano il runtime CUDA, non modificano Γ
e non cambiano i lemmi formali congelati.
