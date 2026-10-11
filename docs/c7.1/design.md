# C7.1 — design

[Specifiche](specs.md) · [Sicurezza](security.md) · [Test locali](local-tests.md) ·
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
conto traffico per tile rettificato a2.442.164.939.108.352B per batch,
zero distinti esclusi; vecchio record immutato, nessuna misura HBM.
Il [primo componente GPU](../c7.1-history/h100-rms-native-prefix-component-2026-10-11.md)
passa18 finestre da12B originali, tre piccoli programmi e chunk512;
conteggi nei registri, nessun piano u32 globale o riga ausiliaria15.
Non è il caller completo. Shared massimo40.896B entro232.448B H100;
il [replay GPU originale](../c7.1-history/h100-rms-native-replay-2026-10-11.md)
passa159 programmi alle profondità GKR1/48/99:1.431 casi,258.022.656
confronti,64 posizioni e tre liveness per programma. Programmi provati
separatamente; momenti misti dei159 programmi e tutte99 profondità GPU
ancora da verificare. Build CPU:18 campioni GPU556.793.856B non attribuiti;
nessuna affermazione di isolamento. Validazione canonica, residuo fold/core
e conto simultaneo restano aperti; nessuna selezione canonica.
Distributività, selector/mask/wire, ricostruzione/count bounds/modulo,
determinismo dei frame e lifetime/capacità CUDA sono premesse non scaricate.
Il [caller GPU comune ridotto](../c7.1-history/h100-rms-common-prefix-2026-10-11.md)
passa sul checkout pulito `c67db510`: wire/FS/MAC uguali, caso onesto
accettato e due alterazioni respinte dai verificatori originali RMS/PCS
e P0/V/RNE/W/A. Fixture28 celle vive/32 padded,93 profondità native;
correlazioni ideali, nessun modello o setup AES canonico. Owner42.280 B,
sette buffer privati per profondità,651 allocazioni/rilasci per prova;
arena massima7.053.056 B e fisico campionato613.847.040 B, senza credito
al picco istantaneo o al conto simultaneo canonico. GPU idle dopo cleanup.
Passano anche owner/trace/pool, simboli/capability Rust e check produzione;
i tre negativi iniziali restano conservati. Fold/core residuo, indici/byte,
momenti misti159/99 profondità e conto completo restano aperti;
nessuna selezione canonica.

La [sorgente originale mapped](../c7.1-history/h100-rms-mapped-source-parity-2026-10-11.md)
passa12 check sul checkout pulito `df8c613e`, inclusa parità del caller
originale:28 celle/93 profondità,652 allocazioni/rilasci, arena7.053.568 B
ed owner42.384 B dopo cleanup. Wire/FS/MAC e verificatori RMS/PCS/P0/RNE/W/A
originali, correlazioni ideali; zero certificati. Fisico campionato618.999.808 B;
build CPU con GPU556.793.856 B non attribuita, nessun isolamento dedotto.
Un solo checkpoint immutabile; nuovi lifetime e traffico mapped restano
nel conto da completare. La [candidata fold/core GPU](../c7.1-history/h100-rms-cell-tail-2026-10-11.md)
passa [14 check sul checkout pulito `53d505a7`](../c7.1-history/h100-rms-cell-tail-parity-2026-10-11.md):
84 insiemi di coefficienti/24 terminali densi originali su16.384 celle,
14 round, tre profondità e challenge zero/uno; callback host frame zero.
Caller originale ridotto wire/FS/MAC e RMS/PCS passa:931 rilasci su931
allocazioni, arena7.693.056 B e owner42.496 B. Negativo header conservato.
Caller fisico campionato620.478.464 B, zero incompleti; fold con un campione
incompleto, build GPU556.793.856 B non attribuita; nessun picco completo.
La [candidata indici e binding/live](../c7.1-history/h100-rms-index-prepared-2026-10-11.md)
ha un [primo negativo owner](../../benchmarks/results/c71-certificates-rms-index-negative-2026-10-11-7ba70443.json)
sul checkout pulito `7ba70443`: compilazione passa, primo round respinto
per coverage initialized assente sul token privato dopo upload/fence.
Correzione registra la coverage solo dopo il fence riuscito; nuovo trial
sul pod, parità ancora da verificare. Tre buffer privati, stessi round/FS/MAC
e stream assignment originale. Byte/statistica GPU,159 programmi/99
profondità, conto completo e raffinamento restano aperti.

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

Una [cache RMS locale candidata](../c7.1-history/local-rms-fold-cache-2026-10-11.md)
conserva al più 16 MiB di righe e selettori già folded, per una sola
profondità. Le parità ridotte conservano wire/FS/MAC; il conto pubblico
riduce i callback di cella da 998.927.195.904 a 718.142.017.536 (−28,11%),
ma lascia **751.359.028.655.932 prodotti Fp3 del core**. Il percorso
canonico mantiene cache disabilitata. Distributività del campo, ordine
MSB del fold, determinismo della sorgente e lifetime Rust sono premesse
implementative: nessun nuovo lemma Lean le scarica. La misura con
il piano condiviso è sopra; conto simultaneo e costo canonico restano aperti.

Una seconda [candidata RMS fattorizza i gate comuni](../c7.1-history/local-rms-shared-gates-2026-10-11.md)
fra programmi mantenendo i polinomi originali. Il primo round Booleano è
invariato; dopo usa il piano condiviso solo quando il supporto pubblico
predice meno prodotti Fp3. Piano/builder entro 32 MiB, per profondità,
separato dalla cache folded da 16 MiB. È disabilitata nel runner canonico.
Distributività, commutatività e corrispondenza fra indici, maschere e pesi
sono premesse implementative esplicite; non c'è un nuovo lemma Lean di
raffinamento. La misura ridotta è sopra; restano necessari conto completo e
valutazione del lavoro residuo nel dominio canonico.

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

La [chiusura locale del 10 ottobre](../c7.1-history/local-exploration-close-2026-10-10.md) registra le esplorazioni successive alla campagna:
verifica degli artefatti conservati, riuso di un solo flag numerico sincrono
(256 B device trattenuti e 8 B aggiunti all'owner host) e quattro screening
di scale A alternative. Il flag viene azzerato prima di ogni operazione;
kernel, letture di stato, fence necessari e controlli restano invariati.
La parità CUDA ridotta delle tre librerie passa nel nuovo preflight;
il pool misura −9,847% in una coppia d’inferenza reale. Il confronto A
è concluso senza vantaggio stabile; l’allowance rimane aperta. Il conto del setup AES
reale include anche cache W e owner già installati.

Γ ammesso resta il riferimento. Gli screening mantengono W, architettura,
workload e ricette numeriche, ma cambiano la relazione tramite le scale A:
non ereditano ammissione o credito prestazionale. Geometria A/PCS e 512
ricostruzioni iniziali restano invariate. Il [piano hardware mirato](../c7.1-history/local-hardware-plan-2026-10-10.md) distingue costo
API/kernel, attribuzione dello spike e validazione numerica/qualità.
L’autorizzazione del seguito ha sostituito il vincolo di solo lavoro
locale, coprendo trial e correzioni entro lo stesso pod, ambito e deadline.
La campagna è ora chiusa; altro hardware o durata non erano inclusi.

Il confronto ridotto prima/dopo misura 32→1 allocazioni del flag, con
stessi 32 kernel, 96 fence e 2.176 B D2H inclusa l'osservazione dei raw.
Il census del caller predice 1.185.769 coppie alloc/free in meno per
inferenza e 6.997.504 nei 512 replay A, senza attribuire guadagni di tempo.
Il massimo nominato del 10 ottobre sul Γ ammesso era **5.878.735.106 B**, con
**26.844.926 B** residui, prima dell’export: il pool è contato anche inattivo e il setup AES
include lo stato W già installato. Allowance e picco fisico restano aperti.

La candidata RMS al pari più grossolano è ora respinta dal criterio
numerico O=0 sopra; conserva soltanto i benefici analitici di componente: 159→91 programmi, −13,9216% di prodotti Fp3 del core
RMS/GKR per risposta O=0 e −43,0563% dei byte posseduti dai soli circuiti.
Il bucket al pari più fine dà −14,4015%, ma la requantizzazione delle
attivazioni ammesse espone rischi i16 in 16/5/2 fonti O=0/150/300.
Entrambe compilano nei tre contesti; profondità 99, celle vive, callback,
checkpoint PYS e geometria PCS restano invariati. Le due variazioni dei
soli output hanno beneficio trascurabile o costo maggiore e sono scartate
come ottimizzazioni. Il possesso dei circuiti non è il picco composto:
Builder, packed replay, allocator e workspace richiedono nuovi bound.
Tutte le candidate restano screening non ammessi; margini, errore numerico,
qualità/token, due replay interi e confronto indipendente restano da validare.

Il [seguito locale](../c7.1-history/local-followup-2026-10-10.md) aggiunge il
fill dello zero pubblico score/Z: 7→0 lanci applicativi nella fixture
identica, senza cambiare raw, controlli, fence, allocazioni o lifetime.
Il census predice 3.840 lanci evitati per scan A completa, 1.966.080 nei
512 replay; non riguarda inferenza né lavoro interno CUDA del memset.
La traccia owner è una build diagnostica esplicita, bounded 16 MiB,
owner 42.128 B (32 B aggiuntivi), con clock comune a journal/monitor e
cleanup fail-closed. Il [preflight della nuova H100](../../benchmarks/results/c71-h100-followup-preflight-2026-10-10-7b0885ad316f.json)
verifica packed/esponenti identici e parità CUDA delle tre librerie. La
traccia completa esaurisce 16 MiB in 2,47 s del primo gruppo, senza
completarlo. La build esplicita `C71_OWNER_TRACE_LARGE_ONLY` omette fence
e alloc/free sotto 1 MiB, conserva gli snapshot e lo stesso cap; richiede
la timeline CUDA esterna per gli eventi omessi. Copertura dello spike e
costo fisico restano aperti. Default e ledger restano quelli sopra.

Passano anche predicato RMS originale, replay packed e supporti GKR su
fixture ridotte pesata/non pesata. Lo screen dai metadati conservati dà
upper packed 325.906.729/191.732.984/193.965.966 B per riferimento/coarser/
finer, compreso fixed storico: differenze fra upper, non memoria risparmiata
misurata. Circuiti e PYS coesistono; altro stato del caller/PCG e picco
dei due ruoli restano esclusi. Nessun nuovo bound completo o ammissione.
Le verifiche hardware del seguito sono eseguite nella campagna ora chiusa
con i risultati e i confini indicati sopra.

Il runner ora esporta ogni risposta completa prima dell’invio e conserva
il completamento dopo il journal del verifier, come nelle
[specifiche](specs.md#esportazione-immediata-del-certificato). Non ci sono
ancora certificati reali: la verifica locale riguarda trasporto,
pubblicazione durevole e rifiuti I/O. Il ledger corrente aggiunge
32.768 B di metadata export a quello storico: massimo nominato
5.878.767.874 B; allowance fisica e completamento rimangono aperti.

La build diagnostica `C71_OWNER_TRACE_PHYSICAL` aggiunge query CUDA ai confini
di allocazione/free/fence e conserva solo variazioni di almeno 16 MiB della
differenza fra memoria CUDA usata e payload native, oltre agli snapshot.
Owner diagnostico 42.136 B, file sempre bounded 16 MiB; non è selezionata
per il runner definitivo e non dimostra un picco fisico completo.

Il monitor del trial con traccia usa `--diagnostic-cache-bytes 16777216`:
la riserva per l’intero file viene aggiunta a RSS+GPU prima del confronto
con lo stesso cap fisico. Owner e stack restano contati nei rispettivi
bound; nessuna esenzione o estensione del limite. La modalità è esclusa
dalla calibrazione e accetta solo zero o il cap completo di 16 MiB.

## Obiettivo e relazione dimostrata

C7.1 dimostra a un verificatore designato l'inferenza intera di un modello
privato e la continuazione della sua memoria di attenzione, chiamata KV.
Tutte le risposte accettate devono usare gli stessi pesi W fissati
all'installazione. Il verificatore apprende i token pubblici e l'esito;
non riceve pesi, attivazioni o valori intermedi privati.

Il modello è la parte testuale di `google/gemma-4-31B`, con
[identità immutabile](specs.md#input-e-identità). La relazione usa la semantica
intera in [specs](specs.md#semantica-numerica): arrotondamento al più vicino
con pareggi al pari, rifiuto degli overflow e softmax `C71-SOFTMAX-EXP30-v1`.
Il nome `gemma31b` nei percorsi del codice identifica questo checkpoint.
Il commitment certifica i pesi installati; la loro provenienza e la qualità
del modello sono proprietà separate.

Un'esecuzione parte da KV vuoto e comprende al massimo tre tentativi.
Ogni tentativo contiene 100 token di prompt e 50 generati; i contesti
precedenti hanno quindi lunghezza O=0, 150, 300. Si certifica anche KV
dell'ultimo token emesso. Qualsiasi errore, interruzione o esaurimento
termina definitivamente l'esecuzione. Non sono previsti rinnovi,
riavvii, importazione di ricevute o prosecuzione dopo un rifiuto.

## Organizzazione del protocollo

Il parametro pubblico Γ fissa modello, scale, tabelle numeriche, disposizione
dei dati e ricette dei circuiti. Il verificatore lo valida e lo possiede
prima di installare W o predisporre correlazioni crittografiche.
La calibrazione deve riguardare i pesi reali e il workload fissato nei tre
contesti. Non è richiesta una certificazione generale della qualità.

L'installazione di W è indipendente dalla chiave del verificatore e dalla
sessione. Il setup crittografico predispone invece una capacità finita di
correlazioni monouso. Prima di ogni prova, il preparatore calcola e valida
tutti i valori privati senza leggere quelle correlazioni. La prova può
ricostruire valori, purché coincidano esattamente con quelli fissati.

Le verifiche matriciali, numeriche, di intervallo e della storia KV
confluiscono in aperture PCS sui valori autenticati originali. PCS indica
il commitment polinomiale e la sua prova di apertura; un nuovo MAC valido
su un valore diverso non chiude il requisito. Ogni risposta usa una PCS
di W, una per ogni A precedente e una per l'A corrente, dove A raccoglie
tutti gli ausiliari della risposta. Non esistono prove PCS per token.

Un unico transcript Fiat–Shamir determina le sfide della prova a partire
dai messaggi già fissati. Il verificatore ricostruisce contesto e storia
dal proprio registro. Brucia l'intera riserva prima dell'uso e promuove
la nuova A e KV solo dopo tutte le verifiche e la registrazione durevole
dell'accettazione. Un semplice ACK non promuove lo stato.

## Costruzione da implementare

Il percorso di implementazione conserva la relazione e l'ordine di verifica
B12, con W packed immutabile, lettura ordinata di A, ricostruzione per
finestre e PCS senza vettori sorgente completi. La configurazione attuale delle
risorse usa 512 ricostruzioni per il commitment iniziale A, stato S1
trattenuto per A e apertura RS mediante resti di polinomi. I parametri e
gli obblighi di memoria sono in [specs](specs.md#pcs-e-ricostruzione-dei-valori).

Il generatore efficiente di correlazioni è il riferimento CPU Seed6,
abilitato esplicitamente da `c71-seed6-reference`, con la premessa
EA-LPN-SL-reg* autorizzata. Il teorema B12 sul bootstrap originario e
questa estensione hanno confini distinti: [security](security.md) espone
le ipotesi e ciò che resta da dimostrare. L'esecuzione di test Seed6
non trasferisce automaticamente i bound B12 al programma completo.

## Stato di implementazione e lavoro necessario

Il runner esplicito `experiment-cuda` collega i 13 producer, inferenza
causale, replay A, PCS/range/GKR, verifica e promozione per O=0/150/300.
È un percorso misto GPU/CPU. La tabella descrive l'integrazione corrente.
La [campagna H100 del 9 ottobre](../c7.1-history/h100-components-2026-10-09.md)
ha compilato sm_90 e passato i 15 test CUDA reali. I benchmark sono
componenti ridotti. Il [commitment W completo più recente](../c7.1-history/h100-setup06-checkpoint-2026-10-10.md)
termina in 190,425 s; risposta canonica e picco fisico completo restano aperti. Gli ingressi di test e il lancio
sorvegliato sono nel
[runbook](runpod-tests.md#preparazione-operativa-della-campagna).

| Parte | Stato e confine |
|---|---|
| Telemetria e XOF | Integrati: fasi e avanzamento durevoli, lavoro/trasferimenti/census, buffering sequenziale da 4 KiB con stream/seek/replay originali |
| Commitment iniziale W | Integrato nel Tree/runner: accumuli esatti, FFT, foglie incrementali e Merkle sul common owner; 32 coset/otto colonne, 128 scansioni analitiche sul pinned |
| Commitment iniziale A | Producer residenti collegati alla PCS, quattro coset/tutte le 128 colonne, istogramma fuso nel primo replay; 512 ricostruzioni conservate, nessun download per riga nel commitment |
| Sali iniziali W/A | Prescan e replay selezionati sullo stream comune, cursore logico e cap originali; niente bande host/upload sali |
| FFT naturale diretta/inversa | Integrata nell'owner, usata dalle query iniziali A e dagli stadi extension PCS |
| Query iniziali A | Reader residente e resti collegati al Tree/runner, con sole valutazioni finali D2H; costruzione dei fattori pubblici CPU, richieste e ricostruzioni originali |
| Query iniziali W | Selezionate nel commitment nativo: packed sigillato e resti sul common owner, senza upload delle finestre W; Horner e catena WHIR D10 esatti |
| Closure lineare | Owner e caller nativi integrati con parità ridotta: una scan originale per round, D·live visite, cinque elementi MAC e flag restituiti; mapping W riusato, nessun getter A sostitutivo |
| PCS S1 e successori | Route canonica collegata a `model.native_original`: singleton, coset/FFT/hash/sali, OOD, retention A dopo apertura del predecessore, fold e contrazioni sul common owner; W continua a leggere il packed originale |
| Query extension A/W | Tre componenti PCS caricate nello stesso passaggio e resti residenti in tutti gli stadi; A legge le plane trattenute, senza ricostruzioni originali aggiunte; sole valutazioni finali D2H |
| Accumulo W Tensor Core | Limb16 esatto selezionato dopo parità CUDA: 5,663× sul componente W da 256 MiB; stesso owner e capacità globali; PCS W completa più recente in 190,425 s |
| QK/PV | Default scalare esatto; candidata MMA con prefisso causale comune e bordo scalare non selezionata |
| RMS misto | Replay Booleano CPU a 64 lane con DAG per depth; primo round esatto e cache compatta delle geometrie pubbliche. Selezione solo senza pattern prefix e con più programmi; coefficienti Fp3 ed endpoint restano CPU |
| Resto della prova | Fattori pubblici, rigenerazione Merkle delle aperture, GKR/MAC, Seed6 reale AES, codec, verifica e journal CPU; tempi completi da misurare |

[canonical_device.rs](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_device.rs)
possiede la sessione numerica: stessa Arc W del commitment, un solo
runtime/stream/arena, tabelle, una generazione di checkpoint/istogrammi
ed una capacità KV per 450 token. Matrix usa quattro MMA INT8 esatte,
Norm soglie u128 e gli altri producer la semantica canonica. Producer e
preparatore non ricevono transcript, monete PCS o correlazioni; le viste
storiche mantengono il prefisso causale. Errori, panic, CUDA assente e
cleanup falliti sono terminali, senza retry o fallback.

I consumer CPU usano staging privato bounded. Range A, query iniziali W/A e query extension sono residenti;
il gather range W usa ancora upload signed per finestre fino a 256 MiB.
Il
[conto tecnico](specs.md#runner-cuda-sperimentale-e-conto-simultaneo)
distingue capacità, trasferimenti e stati simultanei: tetto payload
5.905.580.032 B, più riserva fisica esplicita di 256 MiB, totale
condizionato 6.174.015.488 B e ulteriori 256 MiB di margine. La sufficienza
della riserva e il completamento canonico sono aperti.

La telemetria misura wall annidati, traffico applicativo, census ai
confini delle fasi, ledger cumulativo CUDA e RSS/HWM. Non sommare picchi
separati o contatori cumulativi. Il monitor esterno applica deadline e
arresti fisici campionati. Per l'installazione W sono disponibili campioni
simultanei host/HBM; allowance e picchi completi restano da dimostrare. Non sono acquisiti certificati canonici o misure
D34/D35 complete della prova. La
[parità H100 precedente](../../benchmarks/results/c71-h100-corrected-parity-2026-10-04-d3c2fa95eaf7.json)
riguarda operatori sintetici e MAC originali, non il percorso ottimizzato.

## Risultati attuali e prossime ottimizzazioni

Γ è **ammesso** per modello, byte W, workload, semantica, scale, tabelle
e ricette pinned. Si riusa dopo verifica di identità e impatto delle
modifiche; si ripete la calibrazione solo quando l'ammissione pertinente
è invalidata. È l'unico Γ ammesso finora, non un optimum prestazionale
dimostrato. Cambiare scale può semplificare i circuiti ma cambia la
relazione numerica; lo screen coarser della campagna del 10 ottobre non
eredita ammissione.
La campagna precedente usava `c7e05cf`, che include `24b54d4`;
il seguito parte da `ccbea66b` e conserva gli sviluppi successivi.
I trial canonici nuovi e quelli [precedenti](runpod-tests.md#stato-e-sequenza-operativa) mantengono Γ,
semantica, MAC originali, correlazioni monouso e PCG AES. Ogni nuovo trial
riparte da W e KV vuoto, senza importare una sessione terminale.
Il [setup completo aggiornato](../c7.1-history/h100-setup06-checkpoint-2026-10-10.md)
risparmia 492,620 s (1,330× osservato) rispetto al precedente; i due ruoli
lavorano simultaneamente e i loro tempi non si sommano. Il traffico setup
è invariato a 61.841.366 B. Il microbenchmark cGGM misura 1,475×, senza
attribuirlo automaticamente al setup o alla risposta.

Le configurazioni stack 256 B, pagine grandi consigliate su W e code
compute/copy 1/1 sono validate con parità reale. Nel diagnostico di sola
inferenza il massimo temporaneo scende da 1.474.276.864 a 1.216.531.968 B;
sono scope identici di componente, non picchi canonici completi.
Il batching del prompt esatto rallenta a 132,036 s (+45,71%) ed è
[ritirato](../c7.1-history/h100-prefill-2026-10-09.md). L'inferenza scalare
storica misura 84,382 s; il seguito con pool misura 76,760 s a O=0.
Il caricamento W varia fra i trial e viene
registrato separatamente, senza attribuirne la variabilità ai kernel.

Lo [stop del sesto trial](../c7.1-history/h100-canonical-06-2026-10-10.md)
lascia aperta l'allowance fisica: il payload è sotto cap ma la memoria
GPU salta di 504 MiB fra gli ultimi due campioni. La causa non è dimostrata.
Il diagnostico con code `0.25x` conserva geometria, cap e monete fresche;
non include la ritenzione W/setup e non fornisce credito canonico.
Il profilo pubblico attribuisce 131.072.000 B transienti al RNE finale;
è un'indicazione analitica, senza nuova schedule selezionata. Il timeout
CPU storico dopo circa 41 minuti resta il fallimento della sua schedule
da 1.024 scansioni, non una misura dell'attuale commitment H100.

Il [passaggio operativo](../c7.1-history/crypto-preh100-operations-2026-10-09.md)
conserva 65 test locali, ingresso CUDA esplicito, timeout diagnostico distinto
dal target 65 s e monitor con cap fisici. La [chiusura](../c7.1-history/h100-campaign-close-2026-10-10.md)
registra spegnimento e limiti residui; nuovo hardware o nuova durata
richiedono nuova autorizzazione. I campioni durante transizioni W non
attribuiscono credito congiunto. Raffinamento Seed6/CUDA, allowance,
picco completo e target della risposta rimangono aperti.

Il [checkpoint S1 e Query E](../c7.1-history/crypto-residual-query-2026-10-09.md)
collega owner e caller fino alle query extension di tutti gli stadi.
Le catene WHIR D10 A/W conservano wire, FS/RNG e MAC originali;
getter e finestre host private sono vietati nelle route residenti.
La schedule S1 non-query è preservata e il commitment iniziale A resta
a 512 ricostruzioni. Il [checkpoint W e profilo residuo](../c7.1-history/crypto-local-convergence-2026-10-09.md)
aggiunge query iniziali W, retirement numerico prima dell'hash A e Writer
canonico di capacità fissa. Il profilo sul Γ ammesso quantifica anche il
grande replay Booleano/GKR RMS CPU, ora aggiornato dal
[checkpoint RMS](../c7.1-history/crypto-rms-close-2026-10-09.md).
Preparare soltanto la PCS non chiude il target della risposta.
Fattori, FFT dispari, range e producer restano costi
separati; almeno 581 scan complete dell'A corrente precedono le richieste
parziali e gli altri consumer.

Il [conto tipato del 9 ottobre](../../benchmarks/results/c71-preh100-operational-local-2026-10-09-24b54d414421.json) enumerava 653 fasi e le 11
classi di allocazione, compresi cache/workspace RMS e gli 8 B aggiunti
per seguire il lifecycle W: massimo 5.878.734.842 B e 26.845.190 B residui
nel payload di 5.905.580.032 B. La [chiusura locale del 10 ottobre](../c7.1-history/local-exploration-close-2026-10-10.md)
aggiorna il conto con flag trattenuto, nuovo owner e cache W già vive
nel setup AES reale; il massimo storico non è il bound del codice attuale.
Rimane condizionato alle capacità dei path/argv
≤4.096 B ed alle identità Γ/layout registrate; `joint_admitted:false`
conserva il confine rispetto al picco fisico non misurato.
Il [checkpoint capacità](../c7.1-history/crypto-capacity-close-2026-10-09.md) chiude i bound tipati di profili,
wire/decoder, forme, telemetria, setup AES e compilatore RMS. Preflight
pubblico prima di W/history e compattazione KV preservano byte/FS/MAC;
le batch P/V appartengono a fasi successive, non simultanee.
RMS conserva gli stessi circuiti: `PackedReplay` usa 64 lane ed il DAG
per depth; la cache riduce analiticamente le compilazioni 4.293→1.908.
Il primo round esatto elimina 128.288.785.794.560 moltiplicazioni dal
core coefficienti storico di 972.294.988.954.860, pari al 13,19443%.
La riscrittura successiva a tre prodotti riduce ulteriormente il residuo
da 844.006.203.160.300 a 751.359.028.655.932 prodotti Fp3 CPU.
I 998.927.195.904 callback
del checkpoint per risposta non diminuiscono. Benchmark CPU ridotti con
scale nonzero verificano il replay, senza attribuire tempi al Γ ammesso
o alla H100. La catena AES composta e
un test KV completo rimangono incompleti a 60 s locali; non ereditano
crediti dai componenti positivi. Valutare TMA, fusioni e CUDA Graphs
su costi misurati. Il confronto W ordinario/Tensor sulla H100 giustifica
la selezione Tensor
nel Tree; il [record componenti](../../benchmarks/results/c71-h100-components-2026-10-09-d00d46308029.json)
conserva i campioni esatti e i loro limiti. QK/PV rimane scalare. Il codec cGGM ora
assorbe direttamente lo stesso frame SHAKE, eliminando il buffer heap
per nodo; [parità e benchmark](../c7.1-history/h100-w-setup-2026-10-09.md)
non dimostrano un guadagno temporale. Il primo trial canonico usa
il codec precedente; non attribuire alla modifica i suoi tempi.

Le geometrie fisiche W CUDA 32 coset/otto colonne, CPU W quattro coset
ed A quattro coset sono modificabili con equivalenza esatta e nuovo
conto di scansioni/ricostruzioni, memoria e capacità simultanee. Non
trasferire implicitamente il blocco di colonne W ad A. Sali/pad/root,
ordine naturale, transcript, NoPeek e MAC originali devono rimanere
invariati. Le geometrie escluse restano escluse per le loro premesse;
riaprirle richiede risolvere e verificare la causa.

Gli obblighi prestazionali già quantificati restano visibili: A iniziale
512 ricostruzioni; sali prescan/replay almeno 274.877.906.944 B XOF W e
137.438.953.472 B A per risposta, anche dopo eliminazione degli upload
sali; D15 W/A non cached e un test CPU lookup/GKR/WHIR superano 60 s
locali. Anche i test RMS c0 reale e mixed421 con PCS conservano timeout
a 60 s; non estenderli o trasferire loro il credito delle fixture ridotte.
Cache di riferimento da 16 MiB solo nelle fixture composte non risolvono
tali timeout in produzione. Il ledger conclusivo sostituisce gli screen
parziali; il picco fisico completo rimane da verificare.

**Premesse residue.** I lemmi Lean richiamati in [security](security.md)
non raffinano implementazione CUDA, scheduling, gather, immutabilità
fisica o composizione Seed6. Il replay assume determinismo dei kernel
corretti su W/tabelle sigillati, token fissati e prefissi KV originali;
controlla token rigenerati e copertura, senza un digest privato di tutta
A confrontato a ogni replay. PCS usa v³=v+1, MAC u³=2; gli endpoint
rimangono VOLE-autenticati sugli originali. Test finiti, anche sulla H100
reale, e compilazione sm_90 non scaricano
queste premesse. La selezione W limb16 assume inoltre la corrispondenza
esatta delle istruzioni MMA/shuffle e della ricomposizione intera verificata
su fixture; nessun lemma Lean la raffina.
Il nuovo fill dello zero pubblico assume inoltre la corrispondenza fra
memset ordinato CUDA e output i64 zero, con guardie/flag/fence preservati;
la parità CUDA ridotta passa, senza lemma Lean di raffinamento.
La traccia diagnostica e l'allineamento dei clock sono strumenti di
laboratorio, senza nuovo credito di raffinamento o di picco fisico.

### Evidenze e decisioni

Questa è la mappa dei checkpoint, ciascuno riferito alla propria SHA;
le lacune storiche in tabella non sostituiscono lo stato corrente sopra.
Dettagli di fixture, RSS, tempi, fallimenti e provenienza rimangono nei
record e nelle storie datate.
Ogni nuova integrazione deve avere parità esatta ridotta, benchmark
rappresentativo e conto completo prima della selezione. Le evidenze
locali sono `credit:false`, senza compilazione o esecuzione CUDA.

| Evidenza | Ambito e limite |
|---|---|
| [Ammissione Γ](../../benchmarks/results/c71-gamma-admission-2026-10-07-868a3e8.json) | Due replay interi e confronto indipendente completo sul workload pinned; non certificati canonici |
| [Diagnostica canonica](../../benchmarks/results/c71-cuda-experiment-2026-10-07-868a3e8.json) | Timeout iniziale W, prima delle risposte; [cronaca](../c7.1-history/design-2026-10-07.md) e [runbook datato](../c7.1-history/runpod-tests-2026-10-07.md) conservano risorse campionate e chiusura |
| [Telemetria/XOF](../c7.1-history/crypto-preparation-2026-10-08.md) | Stream/seek/cap, JSONL durevole e positivo Seed6/AES ridotto |
| [Hash W](../c7.1-history/crypto-w-hash-2026-10-08.md), [accumuli/FFT W](../c7.1-history/crypto-w-scan-fft-2026-10-08.md), [Tree W](../c7.1-history/crypto-w-tree-2026-10-08.md) | Incremental hash, valori/campi, root/aperture, transcript/MAC; timeout uncached conservato |
| [Consumer A](../c7.1-history/crypto-a-source-2026-10-08.md), [Tree A](../c7.1-history/crypto-a-tree-2026-10-08.md) | Codec originale, producer→PCS, istogramma, root/aperture e prova composta; timeout uncached conservato |
| [Closure/XOF/confronto Tensor](../c7.1-history/crypto-components-2026-10-09.md) | Componenti esatti e confronto owner; [correzione causale QK/PV](../../benchmarks/results/c71-attention-causal-local-2026-10-09-29a257b4476b.json) distinta dal finding iniziale |
| [Sali owner/Tree](../c7.1-history/crypto-salts-owner-2026-10-09.md) | Stream privato, root/aperture/transcript/MAC e conto aggiornato; gerarchia CUDA non eseguita, timeout CPU conservato |
| [FFT naturale owner](../c7.1-history/crypto-transform-2026-10-09.md) | Diretta/inversa esatte, geometria dispari e guard; primitiva integrata, query caller ancora CPU al source validato |
| [Query iniziali A residenti](../c7.1-history/crypto-query-2026-10-09.md) | Horner, richieste identiche e catena D10 uncached con wire/FS/RNG/MAC originali; extension/S1 e caller lineare ancora CPU |
| [Closure lineare owner/caller](../c7.1-history/crypto-linear-2026-10-09.md) | Codec e coefficienti/endpoints originali, consumo monouso, full wire D10; S1 aritmetico distinto, nessuna parità CUDA |
| [Lifetime PCS e hash extension paired](../c7.1-history/crypto-retirement-short-merkle-2026-10-09.md) | Rilascio batch/prove, BLAKE3 pinned e regressione sali; hash S1 non selezionato, timeout composto conservato |
| [S1 e query extension sul common owner](../c7.1-history/crypto-residual-query-2026-10-09.md) | Route canonica, parità WHIR D10 A/W e guard privati; query iniziali W ancora CPU, conto nominato non ammesso, nessuna compilazione/esecuzione CUDA |
| [Query W, profilo del caller e audit di convergenza](../c7.1-history/crypto-local-convergence-2026-10-09.md) | 14 filtri Rust e tre test Python passano; RMS sul Γ ammesso quantificato parzialmente, timeout della catena AES conservato, quattro classi di capacità aperte |
| [Capacità tipate e preflight originali](../c7.1-history/crypto-capacity-close-2026-10-09.md) | Parità lineare D10 esatta; 653 fasi con bound condizionati, picco fisico e accelerazione RMS ancora aperti |
| [Replay e geometrie RMS](../c7.1-history/crypto-rms-close-2026-10-09.md) | Replay64 su scale nonzero, parità dei conteggi e primo round esatto; fixture GKR completa senza PCS con wire/FS/RNG/MAC, nessun tempo H100 |
| [Chiusura operativa pre-H100](../c7.1-history/crypto-preh100-operations-2026-10-09.md) | 65 test locali, 15 ingressi hardware registrati, trasporto/monitor corretti e ledger aggiornato; nessuna esecuzione CUDA |
| [Regole operative](../c7.1-history/operating-rules-2026-10-08.md), [temporanei](../c7.1-history/temporary-memory-2026-10-04.md) | Ragioni delle decisioni; autorizzazioni correnti definite nel [runbook](runpod-tests.md#autorizzazione-e-limiti) |

## Contratto delle risorse

| Quantità | Requisito |
|---|---:|
| Tempo completo per risposta sulla singola H100 | ≤65 s |
| Certificato completo iniziale, setup di sessione incluso | ≤130.000.000 byte |
| Certificato completo di ogni continuazione | ≤40.000.000 byte |
| Memoria globale H100 | <80.000.000.000 byte, con almeno 1 GiB libero nel piano |
| Arena per tutti i temporanei dell'implementazione | 6.442.450.944 byte, con almeno 256 MiB liberi |
| W packed | 61.394.690.560 byte |

Il codec B12 corrente supera analiticamente 40 MB nelle continuazioni.
La [composizione H100](../c7.1-history/h100-monitor-stack-2026-10-09.md)
del prefisso realmente scambiato e del corpo minimo analitico porta il
primo turno ad almeno 134.174.406 B nei due sensi, distribuzione pubblica
inclusa: supera 130 MB. Non è una dimensione di certificato misurato.
Il ripiego analitico autorizzato è 47,84 / 54,87 / 61,80 MB per
O=0/150/300: sono i limiti inferiori del corpo in
[specs](specs.md#ordine-e-formato-del-certificato), non dimensioni misurate,
limiti superiori o nuovi cap dei certificati. È ammesso concludere così
la valutazione negativa del requisito 40 MB; questa disposizione non
allenta tempo, memoria o sicurezza.

Si conta tutto il lavoro: generazione, ricostruzione del testimone, PCG,
prova, serializzazione e trasferimenti necessari. Il lavoro totale su
ogni prefisso deve essere non crescente rispetto alla baseline a parità
di modello, semantica, token e sicurezza. Caricamento globale e setup di
sessione hanno voci distinte; non vi si nasconde lavoro della risposta.
Memoria aggiuntiva esterna può contenere solo materiale globale del modello,
riutilizzabile senza crescita con le sessioni. Nessuno spill dinamico.
Quattro letture W sono un obiettivo di ottimizzazione, non un limite rigido.

Il budget comune comprende PCS, GKR, Seed6, staging, prove, entrambi i
ruoli e tutte le capacità Rust trattenute, oltre ai buffer CUDA allineati.
Si esclude soltanto il payload W packed immutabile. Le allocazioni grandi
host usano una soglia glibc mmap fissa, evitando che i workspace liberati
rimangano nei successivi picchi come grandi cache dell'allocatore.
Il [conto corrente](specs.md#runner-cuda-sperimentale-e-conto-simultaneo)
separa limite imposto, subtotal derivati dalle shape, test ridotti e
riserva fisica. Il [checkpoint locale](../c7.1-history/temporary-memory-2026-10-04.md)
conserva decisioni, limiti e fallimenti. Nessuna riclassificazione dello scratch della risposta.

I gruppi CPU mantengono 512 scan iniziali A e 1.024 W, ma eseguono
quattro accumulazioni di campo per coefficiente iniziale (due per S1/S2),
con FFT più piccole. Il lavoro extra è della prova: non eredita i tempi
analitici precedenti e non dà credito al requisito di lavoro non crescente.
Restano invariati protocollo, transcript, monete e MAC; non è introdotto
un lemma Lean di raffinamento dell'allocatore o dei kernel. Le assunzioni
numeriche/formali già aperte restano quelle della sezione sicurezza.

## Uso dei documenti

Questi cinque file costituiscono la documentazione operativa. `design.md`
definisce obiettivo e scelte; `specs.md` descrive algoritmi, dati e codice;
`security.md` contiene enunciato, dimostrazione e obblighi residui;
`local-tests.md` e `runpod-tests.md` definiscono verifiche e procedure.
Le [decisioni ed evidenze storiche](../c7.1-history/README.md) conservano
provenienza e fallimenti, senza fornire istruzioni operative concorrenti.
