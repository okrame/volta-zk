# C7.1 — hashing W incrementale, 8 ottobre 2026

Il goal locale dell'8 ottobre resta attivo. Questo passo prepara soltanto
hashing e Merkle del commitment W; accumuli W, FFT residenti e A→PCS
richiedono ancora integrazione e parità. La geometria effettivamente
selezionata dal runner resta quattro coset e 1.024/512 scansioni W/A.
Non è avviata né autorizzata una nuova campagna H100.

## Decisione e motivo

Riutilizzare la compressione unkeyed BLAKE3 di
[P7](../../cuda/p7_blake3_merkle.cu), estratta senza cambiare l'algoritmo in
[c71_blake3.cuh](../../cuda/c71_blake3.cuh). Il formato Merkle P7 non è
quello C7.1: [c71_pcs_hash.cuh](../../cuda/c71_pcs_hash.cuh) implementa i
domini B12, parole little-endian canoniche, quattro sali e parent C7.1.
Non converte o reinterpreta le diverse basi Fp3 PCS/MAC.

Per 128 colonne: dominio 32 B + colonne 0..3 formano il primo blocco;
15 blocchi da otto colonne 4..123 completano il chunk zero da 1.024 B;
colonne 124..127 + quattro sali formano il chunk uno da 64 B. Il parent
dei due CV produce la foglia. Sono 18 compressioni per foglia; il nodo
prefisso 32 B + due digest 32 B richiede due compressioni.

Si trattiene solo un CV da 32 B per foglia. Le quattro colonne pendenti
restano negli slot 4..7 del ring da otto colonne; gli slot 0..3 sono
consumati prima del riuso. Nessuna matrice di Hasher generici da 1.920 B.
I sali sono completati in bande contigue, con una finestra piccola
riutilizzabile, evitando un ulteriore GiB per il gruppo completo.

## Owner e fallimenti

Le nuove operazioni sono nello stesso
[C71RangeContext](../../cuda/c71_range_runtime.cpp), stream, callback del
budget e Arc Rust. Non creano contesti, stream, pool o copie di W.
L'estensione PCS di ABI 4 è obbligatoria per il loader aggiornato; una
libreria priva dei nuovi simboli non è un backend valido.

Valori base, CV incompleti e digest hanno kind distinti. Start → colonne
4,12,..116 → bande di sali in ordine → digest pubblicabile. Ordine,
copertura, span e owner errati fermano il contesto. Il flag aritmetico
rimane vivo fino all'ultima banda e viene verificato dopo fence prima
della pubblicazione. Letture range/original e letture di digest non
permettono di interpretare valori PCS o CV incompleti come output.
Le letture di digest sono limitate a 64 MiB, senza export dei puntatori.

Il [launcher CUDA](../../cuda/c71_pcs_hash.cu) non alloca. Il driver
simulato esegue le stesse funzioni aritmetiche e il vero owner, ma non
esegue scheduling o kernel CUDA. Build sm_90, parità GPU, stack/registri,
latenza e picco fisico restano verifiche della nuova campagna autorizzata.

## Risorse e lavoro

Per 32×2^20 foglie: ring = 2.147.483.648 B, CV = 1.073.741.824 B.
Le quattro colonne pendenti sono già incluse nel ring. Una banda di
65.536 foglie usa 2.097.152 B device di sali e altrettanti host, più
flag device allineato da 256 B. La somma nuova per l'hash è quindi
3.225.420.032 B, prima dell'owner/metadati, degli originali e della PCS.
Tutte le capacità native sono addebitate prima di cudaMalloc e rimborsate
soltanto dopo fence/free riusciti; i layout host passano dal census.

Merkle non aggiunge un'uscita da mezzo GiB mentre il ring è vivo:
la fixture rilascia il ring consumato prima dei livelli. La riduzione legge
un livello e scrive un livello separato, senza alias o race di fratelli.
Lo stride delle righe unisce coset fratelli. Il frontier riceve gruppi
consecutivi, legge soltanto i livelli scritti dai gruppi precedenti e
produce gli stessi sottoalberi per riga dell'ordine naturale. Il test
con 32 coset per gruppo verifica anche seek dei sali, cut roots e root.
Manca ancora il collegamento di questo componente al Tree canonico,
insieme ai suoi accumuli e FFT.

Non è un picco completo: restano frontier candidato W 234.881.024 B
(sette livelli per 128 gruppi da 32, anziché il frontier CPU corrente
da 402.653.184 B; non sommarli), cursori
8.388.608 B, cache superiori W/A, pad, tabelle/potenze, scratch FFT,
stato device 591.277.824 B, layout/host e riserva fisica del design.
Il tetto comune 5.905.580.032 B, riserva 268.435.456 B e margine
268.435.456 B restano invariati. La futura FFT va limitata a un batch
che entri con tutti questi owner; duplicare l'intero ring come scratch
non è implicitamente autorizzato dalla somma 2+1 GiB.

La parità ridotta e il benchmark locale usano 128 colonne, valori di
bordo e casuali, gli stessi sali Rust, tutte le foglie e ogni livello
Merkle. Confrontano byte e root, non soltanto un checksum. Il tempo
host include gli upload di fixture; non è un rapporto di accelerazione
GPU. I risultati e la provenienza sono aggiunti in un nuovo record
immutabile dopo il commit pulito. Nessun input Γ o producer numerico
è modificato; questa ottimizzazione non invalida la sua ammissione.

Il driver host dei test Rust è compilato con UBSan, senza recovery.
Le due parità hash hanno il Budget comune attivo, nessun W esentato,
e stampano il census insieme alle capacità native. I 27 casi negativi
coprono anche gruppi saltati/duplicati, lettura del frontier incompleto,
stride zero, owner estraneo e fallimento del merge. Ogni test resta
entro 60 s / 2 GiB AS, un worker; RSS include anche i processi compiler
discendenti e non coincide con il solo payload della fixture.
