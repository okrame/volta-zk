# PCS residuale e Query E sul common owner — 9 ottobre 2026

Baseline del goal `9033c64`; sorgente finale
`9a5da712a2583be520fe342dfaa278c9651d60fc`.
Il [record combinato](../../benchmarks/results/c71-crypto-residual-query-local-2026-10-09-9a5da712a258.json)
lega la sorgente pulita finale, comandi, binario, manifest e verifiche del
checkpoint unico S1 + Query E. Le fasi preparatorie restano nei record
[lineare](../../benchmarks/results/c71-crypto-linear-local-2026-10-09-31280382f681.json),
[retirement](../../benchmarks/results/c71-crypto-retirement-local-2026-10-09-96b69ded52c1.json)
e [hash extension](../../benchmarks/results/c71-crypto-short-merkle-local-2026-10-09-d16870d8ff1b.json),
senza modificare il loro stato storico. `credit:false`, nessuna
compilazione/esecuzione CUDA, ammissione fisica o misura H100. Il goal è
attivo; hardware e durata di una nuova campagna non sono autorizzati.

## Integrazione e parità

`ReplayModel::make_sourcewise_backend` seleziona nella produzione lo
stesso `model.native_original` già usato da commitment e closure lineare.
Il percorso ora comprende singleton, S1 e successori, coset/FFT/hash/sali,
OOD, retention A tardiva, fold, contrazioni e query extension in tutti
gli stadi. W continua a leggere il packed sigillato, senza retention
completa. Le query iniziali W rimangono CPU; commitment iniziali W/A,
query iniziali A e closure mantengono i checkpoint precedenti.

La verifica locale su `20235da87d851ce856388cd7070c7792cd40089c`
ha completato 15 filtri Rust, compresa la catena WHIR D10 A/W con
2.285.464/2.284.920 B di full wire. FS/RNG, punti ed endpoint dei MAC
originali ideali fissati coincidono col riferimento; due verificatori
controllano la stessa prova. Le fixture installano getter e finestre
host che fanno panic nei percorsi privati residenti. A usa query iniziali
residenti ed un commitment iniziale CPU di riferimento; W conserva il
commitment e le query iniziali CPU della fixture. Queste scelte della
fixture non attribuiscono credito ad un commitment canonico GPU completo.
Il record combinato distingue quei controlli dalle regressioni finali
dopo la rimozione del guard di frontiera descritto sotto: 10 filtri Rust
e quattro test Python passano su `9a5da712`. Le catene D10 A/W passano in
53,88/51,83 s; le prove composte D15 con commitment iniziale nativo
passano in 53,18/53,20 s e conservano 2.736.820/2.735.188 B di wire.
Solo queste fixture D15 mantengono le righe iniziali in cache: non è
una retention autorizzata per la produzione. A D15 verifica separatamente
64 ricostruzioni iniziali e 19 residuali, per 83 totali; il pinned iniziale
resta a 512. Lo scanner canonico e la partizione byte sono ricontrollati.

PCS usa v³=v+1, con marshalling tipizzato distinto da MAC u³=2.
Le parità confrontano codec A i16/raw i48, signed W packed, sfide zero/uno
ed extension, pad, tutti i limb, due coset, root e cursori originali.
Le query Horner comprendono ordine/duplicati, pad 19, cap 1/2/4/8 e
prefissi virtuali A 0..2; nessuna query extension richiama il producer
originale A. Il commitment iniziale canonico A resta a 512 ricostruzioni;
le fixture contano separatamente commitment, singleton, gruppi S1, OOD
e retention, senza confonderli con le query.

I quattro file Python owner/residual/loader/hash sono controlli host,
con algebra indipendente e driver differito. Il loader parallelo W ha
190 casi e 3.024 controlli Horner; l'emulazione CTA conta 191.772 letture
originali, identiche all'oracolo, 8.373 task e 26.934 aggiornamenti di
campo. Il precheck seriale è durato 2,5604 s con RSS 163.201.024 B sotto
AS 2 GiB/60 s. Non è un benchmark CUDA. I log preliminari, compresi errori
di include e warning Werror della fixture poi corretti, rimangono nel
record con provenienza distinta dall'esecuzione pulita.

## Guard, causalità del consumer e risorse

I 19 nuovi simboli ABI4 comprendono nove operazioni residuali, quattro
contrazioni, cinque Query E ed hash paired privato. I filtri dei simboli
sono separati in gruppi di al più quattro librerie mancanti. Capability
e handle sono owner-bound; seal/fold/reader verificano generazione e
posizione c0/c1/c2. La review ha corretto lo scambio c1/c2 prima della
selezione. Query E vincola token, colonna, ordine discendente, grado,
limb e ultimo remainder; le mutazioni FFT generiche durante la query
sono rifiutate. Finish mantiene lo staging fino al fence, valida flag
e canonicità e ritira packet/low/flag prima della pubblicazione. Errori
di producer, symbol, budget, copie, launch/fence/free fermano l'owner,
senza getter o reader sostitutivi.

Un controllo aggiunto alla review provava a mantenere al più 4.096
intervalli byte disgiunti nel C ABI. Il piano pubblico pinned richiede
già almeno 15.360 componenti per i raw_score; l'emulazione dei soli
metadati O=0/150/300 ha misurato un massimo di **52.883**. Quel guard
incompatibile è stato rimosso prima del checkpoint finale, insieme ai
negativi specifici che non appartenevano al contratto originario.
Restano il conteggio/span C e l'unicità del `NativeSource` Rust fidato:
`record_scan_rows`/`complete_scan_rows` rifiutano righe duplicate o
omesse, e la partizione dyadic di `Bytes` mappa esattamente i byte.
La parità di emissioni reversed/ragged è conservata. Non è introdotto
un nuovo assunto di unicità ricavato dal solo conteggio C; la frontiera
ridondante da 65.544 B non rimane nel layout owner finale.

Il loader W precedente assegnava un coefficiente ad un thread e iterava
serialmente tutti i prefissi: nel piccolo S8 pinned, solo 64 coefficienti
per colonna potevano richiedere 119.911.505 letture ciascuno. La correzione
nel medesimo checkpoint usa 32 coefficienti × 256 prefissi × 8 worker,
riduzione modulare esatta e CAS Goldilocks, con guard index/live prima
della lettura. Shared 12.288 B, grid≤8.192 e task≤2^25; nessun nuovo buffer
globale oltre a low3, nessuna retention W o scansione A aggiuntiva.
Il conteggio distingue un launch init/pad ed il secondo soltanto quando
ci sono contributi W. La parità host non misura la contesa CAS o la H100.

I conti tecnici e i lifetime sono centralizzati nelle
[specifiche](../c7.1/specs.md#pcs-residuale-e-query-extension-residenti).
Il subtotal Query E al cap è 864.028.160 B device più packet/flag;
la pubblicazione host richiede contemporaneamente 144q B, non soltanto
la colonna Rust. A S1 conserva 3.221.225.472 B, con 4.026.531.840 B old+new
durante la promozione a due fold. Query scratch termina prima della
rigenerazione del batch corrente; i batch già aperti restano vivi.
Retention A segue il rilascio dell'oracolo iniziale. Batch/prova W
terminano dopo la chiusura W secondo il receipt di retirement, mentre
cache A1..A3, wire e realloc mantengono i rispettivi lifetime.

Il ledger per backend/fase seleziona esplicitamente il percorso
`s1-prepared` per tutti gli stadi extension nativi, ma resta
`joint_admitted:false`: le classi aggiuntive elencate
nelle specifiche non hanno ancora tutte un upper congiunto. Nessuno
slot fisso sostituisce numerica/GKR, fattori CPU, PCG/VOLE, proof/codec,
righe/path già aperti o capacità trattenute. Il limite payload
5.905.580.032 B e la riserva fisica 256 MiB restano invariati. Il nuovo
layout owner è verificato a 42.088 B, Stats 152 B e API +152 B; il record conserva
le dimensioni definitive verificate, senza derivarne un picco canonico.
Il ledger enumera 460 fasi nominate. Il massimo A3 hash è 5.845.536.852 B:
restano 60.043.180 B prima delle 11 classi aggiuntive non quantificate.
Nessun subtotal supera da solo il payload, ma questo non dimostra che
le capacità aggiuntive ci stiano. Il conto simultaneo resta aperto.

## Limiti del risultato

La build mirata ed i test seriali mantengono un job, crate Rust O0,
dipendenze O2, LLD della toolchain ad un thread, overflow checks e limiti
AS 2 GiB/60 s dei test. Comandi, RSS/wall, eventuali timeout ed errori finali
sono nel record combinato; il costo della build è separato dal riuso.
La compilazione preliminare pre03 è terminata per timeout a60,05s;
la singola ripresa pre04 ha completato la build in56,19s. Entrambe
restano evidenze distinte; le regressioni definitive hanno i propri log.
Il wrapper finale ha incontrato un confronto errato fra percorsi assoluti
e relativi del binario dopo il successo W; il receipt è conservato. La
correzione ha riusato entrambi i risultati A/W, senza ripetere i test.
Il benchmark host dell'helper D15/D17 è eseguito sul binario C++ già
compilato dal controllo finale: fasi helper 10,47/40,11 ms, heap nominato
1.344.576/5.105.144 B, stack 12.288 B. Non è uno speedup GPU né un confronto
fra la build Rust O0 e C++ O2.
Nessuna precedente failure è convertita in successo o sovrascritta.

Restano query iniziali W, profilo delle fasi residue e conto completo
di capacità/lifetime. Compilazione e parità CUDA, consumo fisico,
contesa/sincronizzazioni e tempi separati installazione/setup/inferenza/
prova/verifica richiedono la futura campagna autorizzata. La catena D10
non è un certificato D34/D35 o una misura dei target 65 s/40 MB; i limiti
formali e le assunzioni residue rimangono nel
[design corrente](../c7.1/design.md#risultati-attuali-e-prossime-ottimizzazioni)
e nella [sicurezza](../c7.1/security.md).
