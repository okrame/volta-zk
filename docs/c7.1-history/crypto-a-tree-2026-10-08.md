# A residente nel Tree PCS e residui — 8 ottobre 2026

Checkpoint locale successivo al consumer A, source commit
`2603bbb04013fa8909702164dd76ae74d79646ff`, composto da `c0e65b7`
(fence), `b9460b1` (sali), `3a5e9df` (Tree/runner A) e `2603bbb`
(candidata Tensor Core). Baseline `9033c64`; Γ mantiene le identità ammesse.

Il [record pulito](../../benchmarks/results/c71-crypto-a-tree-local-2026-10-08-2603bbb04013.json)
ha SHA-256 `694095bbd5138dfec472b9d9b553307dec47528b29f3d7879d69e0d655663e37`,
18 test Rust e 12 Python positivi, 69 artefatti e cinque esiti negativi
preliminari conservati. Tree A D15 confronta root, pad, aperture duplicate/
fuori ordine, istogramma e lavoro esatti; 64 ricostruzioni, zero getter e
zero scan CPU iniziali. La fixture comprende originali i16 e piani i48
basso4/alto2 (`byte_first=4,width=2`). Lo scanner reale continua a garantire
la partizione tramite copertura delle righe delle sorgenti; i nuovi negativi
verificano sovrapposizioni/omissioni. Il C ABI controlla solo span e totale,
non è una guardia autonoma di unicità.

`Snapshot::Native` seleziona A→accumuli→FFT→foglie/Merkle→Tree sul medesimo
owner; CPU mantiene il riferimento. Il producer non riceve monete PCS,
correlazioni o transcript. Il consumer lascia il lock prima dello scanner,
chiama finish soltanto dopo successo completo e ritira potenze/istogramma
prima dell'hash e valori prima del Merkle. L'istogramma della prima scan
riempie il cache range, includendo il suffix zero pubblico: nessuna nuova
ricostruzione. R=2^20/quattro coset/tutte128 colonne conserva512 sul pinned.
I profili ridotti dominati dai1536 pad richiedono il loro H originale più
grande di16n; il gate Tree conserva sempre il config originale. Il test
negativo dell'ABI ora usa un rate inferiore16; il vecchio fallimento del
rate32 rimane nel raw con le sue premesse precedenti.

Le prove composte W/A confrontano wire, transcript, RNG, MAC originali e
doppia verifica; solo la fixture sostituisce le righe iniziali con una
tabella del riferimento da16MiB, conteggiata. I test Tree separati usano i
getter effettivi. D15 A senza cache ha raggiunto60s, come W precedente:
obbligo aperto, ora ignored e mai contato come pass. Il suo primo raw non
ha Recording attivo e contiene soltanto il prefisso stdout; il test nuovo
ha Recording anche nel ramo ignored. Nessuna estensione del limite.

Cinque negativi preliminari: D14 ha firstfold1/due colonne (fixture inadatta
al128col canonico); SourceShape16n rifiutava il rate originale D15 dominato
dai pad; test helper chiamava API Rust privata; vecchio negativo rate32
ora legittimo; prova A uncached oltre deadline. La review ha inoltre
corretto il conteggio tessera `width-byte_first` in `width`, coperto dal
nuovo piano alto i48. Non si sovrascrive alcun record precedente.

Ogni test usa60s/AS2GiB, un worker, processi seriali; RSS massimo test e
compilatori discendenti250.183.680B. Build completa preliminare57.02s e
2.474.213.376B separati. Cargo pulito0.164s riusa lo stesso binario,
con digest/source dichiarati; non è nuova compilazione completa. La fixture
Tree A ha nativepeak1.879.808B e payload congiunto4.830.711B; la prova
composta include il cache16MiB e le sue fasi/allocazioni nei log; il
payload congiunto massimo delle tracce W/A è101.150.239B. Lo screen
canonico A rimane5.578.870.016B prima degli altri owner host, con326.710.016B
residui; non è un picco simultaneo pinned o fisico ammesso.

Il batch32B `salts4` conserva candidati/rejection/cursore/cap. Tre test
confrontano il sampler pinned, rejection forzate P/P+1/MAX, seek e ultimo
cap. Benchmark stesso binario, tre rep e ordine alternato: strided
0.04219→0.02919s per65536 foglie, rapporto1.445. Sequential già bufferizzato
0.01837→0.02198s: batching non selezionato lì. Nessuna estrapolazione H100.
`dense_complete` ritira il flag immediatamente dopo il suo fence valido,
con contabilità e free-failure terminali; API release pubblica invariata.
Il driver differito verifica successo e errori flag/fence/free.

La candidata W limb16 è separata, non selezionata nel runtime: quattro
digit biased, dot INT8 esatto con pack/compose esistente e correzione
32768*sum_W; −32768 è legale per il digit, terminale negli originali W.
Shared8448B, nessuna nuova allocazione globale. Per q256:512 MMA/CTA,
262144B di letture logiche high,8192B W,4096B output; quattro colonne×quattro
righe×32coset. Test emulazione fragment/shuffle contro signedi128/%p:
262144 digit check,14336 dot output,720896 valori PCS,42467328 prefissi,
5808 letture W originali. I cinque rifiuti verificano add_dot, non le
guardie CUDA. Mancano hook owner di confronto, compilazione sm90, registri/
spill/traffico effettivo e prestazioni; nessun credito GPU.

## Costi residui dal codice

Sono conteggi analitici, non tempi o traffico fisico. Il lavoro XOF ripete
lo stesso stream del root, senza consumare due volte la riserva logica.

| Fase | W | A per risposta |
|---|---:|---:|
| Sali iniziali prescan+replay | 34.359.738.368 campioni | 17.179.869.184 campioni |
| Byte XOF minimi elaborati | 274.877.906.944 | 137.438.953.472 |
| Byte sali H2D | 137.438.953.472 | 68.719.476.736 |
| Upload/fence banda65536 | 65.536 | 32.768 |
| Celle FFT iniziali | 549.755.813.888 | 274.877.906.944 |
| Butterfly radix2 R2^20 | 5.497.558.138.880 | 2.748.779.069.440 |
| Getter nella linear closure D*2^D | 1.202.590.842.880 | 584.115.552.256 |

A iniziale visita6.458.234.182.656/6.835.721.542.656/7.213.208.902.656 byte
per O0/150/300, con quattro contributi per byte. S1 non-query aggiunge35
passaggi (singleton,32gruppi,OOD,retention), rispettivamente441.480.852.330/
467.285.652.330/493.090.452.330 visite. QK+PV scalari contano per replay
12.988.416.000/38.793.216.000/64.598.016.000 prodotti, da pagare nelle512
ricostruzioni. Query iniziale: cut4096, fino512 sottoalberi, cap2^20 e fino
due batch; output128col1.073.741.824B e fattori704.643.072B oltre workspace.
I conteggi GKR storici non sostituiscono il ramo corrente `patterns::Table`:
servono contatori pattern.Work/SourceCellWork/byte endpoint.

Priorità successive: GPUXOF bounded esatto; scan lineare per round e indice
pubblico dei Cube; query/S1/range/GKR e QK/PV residenti, fusioni e fence.
Matrix→RNE può conservare raw e rounded originali con un flag; Graphs
richiedono segmenti con capacità stabili fuori dalle coin FS; TMA richiede
profilo hardware. Queste sono candidate da verificare, non ottimizzazioni
integrate. Rimangono tutte le premesse Lean/B12/Seed6, NoPeek, MAC originali,
correlazioni monouso e PCG AES reale. Il goal resta attivo; H100 e durata
richiedono nuova autorizzazione al termine della preparazione locale.
