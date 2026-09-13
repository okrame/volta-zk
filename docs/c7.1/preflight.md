# C7.1 — preflight locale, 2026-09-13

**NO-GO per H100.** Lo screen dei costi dominanti respinge il getter che
rigenera tutta A con prodotti scalari a ogni visita: il solo commit A
impone >=135,257 s nelle condizioni esplicite sotto. Le specializzazioni
range/FFT/apertura per resti riducono il lavoro, ma il loro lower parziale
non esclude una costruzione diversa entro 50 s. Upper completo e picco
completo restano aperti. **90 s è una soglia di discussione del proprietario,
non una deroga autorizzata.** Nessun pod, spesa o esecuzione GPU.

I conti riproducibili sono in
[`integrated_resource_ledger`](../../scripts/c71_streaming_screen.py) e
[`c71_query_remainder.py`](../../scripts/c71_query_remainder.py), `credit:false`.
`null` significa ignoto; il corrispondente upper di ammissione è **+infinito**.
Non è possibile dare un upper completo finito usando soltanto un picco di
banda e componenti ancora privi di implementazione e contratti temporali.

## Lower di banda e calcolo separati

Per uno stadio k, `max(B_k/BW_max,I_k/R_max)` è un lower. Sommare i lower
solo tra stadi distinti obbligatori; non sommare IO e calcolo dello stesso
kernel come se fossero seriali. Un upper richiede invece limiti al lavoro,
throughput **minimi garantiti per quel carico** e attese massime; non si
ottiene invertendo picchi, medie o percentili.

Il riferimento [H100 SXM](https://www.nvidia.com/en-us/data-center/h100/)
ha 80 GB e 3,35 TB/s nominali. Lo screen condizionato usa `BW<=3,35e12 B/s`,
allocazioni senza compressione e credito cache **<=256 MiB per traversata**.
Per una sorgente packed di S byte, Q coset da 4 GiB e cinque passaggi
FFT separati, prima di hash/sali/ricostruzione:

```
HBM_lower(S,Q) = Q * [(S - 256 MiB) + 10 * (4 GiB - 256 MiB)]
```

La sola FFT globale letterale a 22 passaggi richiedeva >=54,155 s per
encoding W; resta scartata. La FFT a cinque passaggi riduce questo costo,
ma nella risposta occorre aprire W, committare **e** aprire A corrente,
e aprire ogni vecchia A. Il census finale EXP30 fornisce A packed da
13.154.672.538 / 14.334.320.538 / 15.513.968.538 B. Sono byte effettivi
della sorgente, non celle RNE ripetute o Fp3 densi.

| O | Visite W primo oracolo | Visite A per generazione | HBM lower primi oracoli, TB | Lower banda, s | Più lower merge W, s |
|---:|---:|---|---:|---:|---:|
| 0 | 1.024 | 1.024 | 158,252164 | 47,239452 | 52,884727 |
| 150 | 1.024 | 512 / 1.024 | 186,673720 | 55,723499 | 61,368774 |
| 300 | 1.024 | 512 / 512 / 1.024 | 215,699256 | 64,387838 | 70,033113 |

Queste cifre concedono gratis la disponibilità packed di A. Escludono
oracoli successivi, range A, altri prodotti di campo, PCG, inferenza e
serializzazione. Le continuazioni sono escluse già dalla banda sotto le
condizioni dichiarate. Non è un lower universale sulle PCS o sul prover.
Il commitment W installato si paga separatamente: altre 1.024 visite e
>=30,992529 s in questo metodo; includerlo nel confronto dei prefissi.

Il binario range compilato con CUDA 12.9.1 contiene **149 istruzioni
`IMAD.WIDE.U32` incondizionate** per merge valido, prima dell'uscita,
senza ciclo/call nel corpo. Su 640.151.453.695 merge, con 132 SM,
<=64 risultati multiply INT32/ciclo/SM e ceiling esplicito **2 GHz**,
questa sola classe impone >=5,645275 s. Il ceiling di clock è una
condizione dello screen, non una misura della macchina futura. Il bound
vale per il kernel generico compilato; fusioni/specializzazioni diverse
richiedono un nuovo census. La
[tabella NVIDIA](https://docs.nvidia.com/cuda/archive/12.9.1/cuda-c-programming-guide/index.html#arithmetic-instructions)
non autorizza conversioni da TFLOPS Tensor Core a prodotti Fp/Fp3.

## Alternativa minima: aperture per resti, cache e range coordinati

Conservare i nodi Merkle sopra sottoalberi da **4.096 foglie**, con gli
offset iniziali dei sali canonici. Per W e fino a tre A, questa cache
privata costa **188.743.552 B**: 167.772.032 nodi in byte e 20.971.520
offset in byte. Non contiene correlazioni riutilizzabili e non aggiunge
emissioni. Le query restano successive al commitment.

Dopo le query, al più 512 sottoalberi richiedono B=2^21 righe. B è un
**cap algoritmico fisso**, indipendente da N e dal numero effettivo q;
completare con punti distinti deterministici del dominio originale se
necessario. Per `Z(X)=prod(X-x_i)`, consumare i coefficienti sorgente,
pad privati originali inclusi, a blocchi high-to-low:

```
r <- (r * X^B + f_i) mod Z
```

Precalcolare FFT del reciproco di `reverse(Z)` modulo X^B e FFT(Z).
Il quoziente usa soltanto i B coefficienti alti invertiti: includere
anche quelli bassi causa alias ciclico. Due convoluzioni con fattore
fisso costano **quattro FFT di lunghezza 2B=2^22 per blocco**. Il test
ora esegue proprio questi quattro transform, con due precalcoli condivisi.
La FFT quadrata 2048² già compilata è riusabile; inverse, normalizzazione,
packing e pipeline remainder CUDA restano da collegare.

Per N coefficienti base, arrotondati a blocchi, il nucleo sorgente paga
**88N butterfly + 8N prodotti twiddle + 4N prodotti spettrali + 4N
normalizzazioni inverse**, una scansione sorgente; ogni butterfly include
un prodotto e due somme. Aggiungere shift del dominio, pad, layout,
costruzione reciproco/alberi e valutazione multipunto veloce. Questi
ultimi termini sono `P(q,h)` indipendenti da N con il cap fisso: i piccoli
helper quadratici del test non sono il piano canonico. Il requisito
`c_source*N + P(q,h)` è soddisfatto da questo **nucleo di apertura**;
non è ancora dimostrato per commitment, WHIR e intera costruzione.

Le righe ottenute devono coincidere con quelle originarie. Ricostruire
sali e sottoalberi inferiori, poi prendere i fratelli superiori dalla
cache. Non cambiano punti MAC, root, codec, ordine FS, pad o trust model.
Il confronto finito verifica divisione, righe selezionate, pad privati
non nulli, zeri pubblici e blocco iniziale parziale; manca il confronto
bit-per-bit contro l'intera PCS nativa e la sua disciplina NoPeek.

La prima proposta h=10/B=2^19 richiedeva 754.974.592 B di cache su tre A:
non entra con il range m25. Anche h=12 non entra nei 127.377.416 B liberi
di quella fase. La variante coordinata usa **cut=11, residente m=24**:
**29 visite W**, 740.982.521.855 merge e 3.469.226.278.261 mul Fp3 del
nucleo fattorizzato. Cambiare soltanto m senza il canopy lascia un picco
incompatibile. Il range A/D34 può usare cut=10/m24: 26 visite A e
1.571.622.485.383 mul Fp3 del medesimo nucleo, più getter/istogrammi/MAC.
Sono replay della stessa algebra range, non un protocollo indebolito.

## Test decisivo sui costi dominanti

Il nuovo `dominant_cost_screen` separa il replay scalare escluso dalla
variante specializzata ancora aperta. I lower di istruzioni assumono
132 SM, clock <=2 GHz, <=4 emissioni warp/ciclo/SM e 32 lane/warp; il
ceiling scalare è <=64 risultati INT32 multiply/ciclo/SM. Sono condizioni
esplicite, non misure, né throughput minimi di servizio. Vedi architettura
[Hopper NVIDIA](https://developer.nvidia.com/blog/nvidia-hopper-architecture-in-depth/)
e la tabella CUDA linkata sopra. Gli stadi sommati sono distinti nel piano
letterale: non si presume overlap. Un kernel fuso diverso richiede un
nuovo conteggio; non eredita automaticamente questi lower.

**Getter A scalare.** Le 411 coorti matrice richiedono almeno
4.463.473.459.200 MAC interi per rigenerazione completa di A sui 150 token.
512 rigenerazioni per il solo commit impongono >=135,256771 s. Con le
540/542/544 rigenerazioni già note (incluse vecchie A e una ricostruzione
S1 dopo query), il getter solo impone 142,654/143,182/143,710 s. Questo
esclude 50 e 90 s **per il replay completo con MAC scalari**, senza
pretendere un'impossibilità per Tensor Core esatti, cache o getter fusi.
Non comprende ancora i replay di commitment del primo switch sotto.

Tre specializzazioni riducono lavoro, senza cambiare il predicato:

- `mul6` usa sei prodotti base per Fp3 invece di nove. Il merge compilato
  richiede 1.183 istruzioni incondizionate anziché 1.379. La coppia di
  foglie ha numeratori uno: con x,y uint16 e alpha traslata dello stesso
  bias pubblico, `P=2alpha-x-y`, `Q=alpha²-(x+y)alpha+xy`. Alpha² è
  precalcolata, xy è esatto in u32; il kernel ha 231 istruzioni.
- Un sottoalbero di n=2^h zeri **pubblici** restituisce la coppia esatta
  `(n*alpha^(n-1),alpha^n)`, precalcolata in O(d). Si saltano le sue
  moltiplicazioni di ricostruzione, **non** le celle virtuali nel GKR
  pesato: P/Q sono non nulli. Il bias delle foglie W non cambia lo zero
  originale di questa formula. Il range W passa da 740.982.521.855 merge
  generici a 383.716.816.000 leaf-pair e 278.284.625.245 merge interni.
- La FFT usa shift/mask per indici di potenze di due e bit-reversal CUDA.
  Spariscono CALL/divisioni/reciproci dal kernel di riga. Il ciclo della
  butterfly contiene 77 istruzioni incondizionate nel binario compilato;
  questo census vale per quel kernel quadrato, non per ogni FFT piccola.

Le aperture sfruttano anche `f(X)=f_live(X)+X^M pad(X)`: il suffisso zero
pubblico non richiede replay. Si calcola il resto del payload e si aggiunge
`(X^M mod Z)*pad mod Z`, con **gli stessi pad privati**. Partire da
`X^B=-Z_low mod Z`, poi log2(M/B) quadrature modulari; shift e spettro sono
condivisi tra 128 colonne. Il [layout nativo](../../rust/third_party/p3-whir-c61/src/pcs/zk/committer.rs) divide il messaggio in chunk
contigui prima di trasporre: il prefisso live occupa ceil(L/B) blocchi,
non 128 code parziali distribuite uniformemente. Sei FFT per quadratura, sei per correzione pad
con spettro fisso, più una FFT dello shift. Il piccolo helper algebrico usa
una moltiplicazione generica (sette FFT), non è il runtime del piano a sei.
Saltare blocchi zero intermedi nel vecchio Horner senza lo shift sarebbe
errato. Questo nucleo resta `c_source*N + P(q,h)` con B fisso.

| O | Range W+A, solo merge specializzati, lower s | Commit A, max(FFT HBM, issue), lower s | Prime aperture W e tutte A, issue lower s | Somma parziale, s | Con getter scalare, s |
|---:|---:|---:|---:|---:|---:|
| 0 | 16,868684 | 6,889843 | 8,963441 | **32,721968** | **175,375595** |
| 150 | 17,272523 | 6,889843 | 11,922764 | **36,085131** | **179,267104** |
| 300 | 17,676362 | 6,889843 | 15,118421 | **39,684627** | **183,394946** |

La FFT commit A muove >=20.615.843.020.800 B secondo il credito cache
fissato, lower banda 6,153983 s; non sommarlo al suo lower issue. Le prime
aperture specializzate costano 3.933.669.949.440 / 5.232.390.045.696 /
6.634.826.891.264 butterfly. Restano fuori Gram, coefficienti, pesi,
fold, scaling commit A, hash/sali, query product tree, oracoli successivi,
PCG, getter non scalare, inferenza e serializzazione. **La colonna parziale
non è un upper e non dimostra né 50 né 90 s.** I probe standalone Fp/Fp3
includono load/indirizzi/controllo: moltiplicarne il census per tutti i
prodotti inlined produrrebbe un falso lower.

### Getter A/KV: contratto minimo e alternativa strutturale

Un getter riceve solo snapshot originale/ID sorgente e intervallo pubblico;
risolve ricetta, riga, colonna e byte nel layout originale. Riproduce i token
originali già fissati (teacher forcing), lo stesso Gamma, RNE/EXP30, padding
e maschere causali del relativo O. Usa soltanto il prefisso KV originale
accettato di quel contesto, anche quando esistono token successivi. Non
accetta un nuovo witness dal chiamante o dal transcript. Produce per tile
una word raw e tutti i byte/RNE derivati insieme; nessuna inferenza per
singolo byte. Il suo ordine di lavoro è pubblico, con terminali MAC
originali e nessuna dipendenza da Delta. Il costo dei replay W/KV resta
separato dall'inferenza iniziale che ha prodotto la risposta.

Il primo cap proposto è **64 MiB** per tile di layer/row e lm_head a blocchi;
è uno slot da implementare, non un upper già dimostrato. Il KV originale
usa l'append unico sotto. Cache di tagli intermedi o batch di coset sono
leciti solo contando i buffer contemporanei; il commit iniziale lascia
poco margine. Fusione raw→byte→RNE e range con istogramma riduce lavoro
ripetuto; non può anticipare alpha o query prima dei relativi messaggi.

La minima alternativa al replay scalare è un prodotto i16 **esatto** con
quattro dot-product signed-int8, correzioni affini e ricomposizione i64:
per `x=256*h_x+l_x+128`, `h=x//256`, `l=x%256-128`,

```
x*y = 65536*h_x*h_y + 256*(h_x*l_y+l_x*h_y) + l_x*l_y
      + 128*(256*(h_x+h_y)+l_x+l_y) + 16384.
```

Con K massimo 21.504, ogni accumulatore int8 è limitato da
K*128²=352.321.536 <2^31. Le somme di righe/colonne e la ricomposizione
si pagano, prima dello stesso RNE originale. Il test finito include estremi
signed e cambi di byte; non implementa MMA, tutte le ricette A o inferenza.
Il lavoro base è **8*4.463.473.459.200 operazioni int8 per rigenerazione**
(contando multiply/add separati), più correzioni. Nessun TOPS teorico è
usato come upper di tempo o come throughput Fp3. Il controllo minimo è un
microkernel i16/GEMM esatto su shape e tile pertinenti, poi un trace getter
piccolo con tutte le ricette e dipendenze; non occorre ancora portare Gemma.

## Schedule, liveness e picco allocato/riservato

Ordine FS invariato: fissare snapshot e output; messaggi dei producer e
MAC; istogrammi prima di alpha/rho; range W, range A e relativi target;
batch linear W con lambda dopo tutti i target; primi 15 round suffix-first;
seconda scansione e ultimi 20 round; PCS nel punto originale. I tempi
commit A e apertura non sono anticipati oltre le dipendenze del transcript.
Ogni riuso attende ultimo consumer e completamento GPU.

Piano di allocazione: una sola arena riservata da **6.442.450.944 B**;
la cache Merkle vive **dentro** l'arena durante tutte le fasi. La tabella
conta anche destinazioni fold fuori posto e istogramma W da 524.280 B.
Sono upper dei buffer nominati/cap proposti, non picchi misurati.

| Fase | Byte pianificati, cache inclusa | Fine vita e costi ancora da chiudere |
|---|---:|---|
| Canopy cut11 | 3.376.938.824 | Tree 1.610.612.688, child/eq 1.006.632.960, fold dst 503.316.480, scratch 64 MiB; rilascio dopo terminale top |
| Finestre Gram | cache + istogramma + slot 256 MiB | H <=24.576 B, child <=3.072 B, worker fissi; nessuna H per tutti i bucket |
| Range residente m24, W o A | 3.480.760.184 | Array/riduzioni 3.023.056.896 + scratch 256 MiB; rilascio dopo terminale |
| Suffix-first W, 15 round | C 2.848.456.704 + cache + scratch vivo | C rilasciata prima della seconda scansione; pesi/getter ancora da assegnare |
| Seconda scansione linear W | B/L 50.331.648 + cache + scratch vivo | Rilascio prima PCS; linear A e vecchie A separati |
| Commit PCS iniziale per coset | 6.197.215.896 | 5.739.381.472 nominati + cache + slot reader/hash 256 MiB + istogramma + output PCG 128 KiB + carry 64 B; restano 245.235.048 B |
| Apertura per resti | 5.402.895.408 | Include output 2 GiB, alberi/fattori FFT, cache, metadata, reader/hash, PCG output e cap proof; dettagli sotto |
| Producer A/KV, WHIR successivo, PCG completo | Ignoto | Non assegnare a zero; nessun picco completo accreditato |

Per l'apertura, un piano prudente conserva tutti i polinomi, reciproci e
due trasformate fisse di ciascun nodo dell'albero bilanciato, anche quelli
non strettamente necessari: rispettivamente **402.653.176 / 369.098.752 /
1.476.395.008 B**. Una colonna alla volta usa quattro workspace FFT da
32 MiB, due livelli di resti da 16 MiB, un resto sorgente da 16 MiB,
punti da 16 MiB, twiddle da 32 MiB e shift/spettro pad da 48 MiB. L'output selezionato da 2 GiB vive
nel riuso dell'arena PCS, senza coset/frontier da 5,739 GB ancora vivi.
Aggiungendo cache, slot metadata 128 MiB, reader/hash 256 MiB, istogramma,
PCG output e **130.000.000 B di output proof**, i buffer nominati occupano
**5.402.895.408 B**, lasciando 1.039.555.536 B prima degli altri stati.
Gli slot e le FFT di grado inferiore richiedono ancora il port nativo;
questa è una prenotazione analitica, non una traccia di malloc. La discesa
multipunto con quattro FFT per nodo ha un upper di 248.034.361.344
butterfly per 128 colonne, oltre al nucleo sorgente e alla costruzione
degli alberi. Nessuna valutazione ingenua B² è ammessa come costo canonico.

Le altre righe della tabella escludono l'output proof: riservando anche lì
130 MB, il maggiore subtotal diventa **6.327.215.896 B** nel commit PCS,
con soli 115.235.048 B residui. Non attribuire quel margine al PCG completo
o ad altre allocazioni senza verificarle. Non si presume emissione anticipata
della proof per liberare memoria prima del punto consentito dal transcript.

Il top Merkle/offset completo è contato anche durante il commit corrente:
non si sottrae la cache in costruzione. Gli slot di scratch sono cap da
implementare. Il buffer output PCG proposto è 4.096 righe base, 131.072 B, più carry 64 B;
non limita automaticamente seed, OT, cGGM e altri stati del backend.

KV originale costa **4.915.200 B/token**. Prefisso accettato:
0 / 737.280.000 / 1.474.560.000 B; con coda pendente da 150 token:
737.280.000 / 1.474.560.000 / 2.211.840.000 B. Proposta: un solo buffer
KV modello persistente prenotato per 450 token, append nella coda
inutilizzata, promozione del cursore solo dopo accettazione. Questa
classificazione vale solo per KV originale, non per witness o workspace;
la coda pendente è sempre contata nel picco globale e non sovrascrive
il prefisso. Se l'implementazione usa staging temporaneo, conta nell'arena.

W + riserva KV450 + arena = **70.048.981.504 B**; rimangono
**9.951.018.496 B** sotto 80 GB per runtime/context e altri residenti
ammissibili. Non autorizza spostare temporanei fuori arena. Una copia
packed completa di A non entra nell'arena; W+A+arena superano già 80 GB
anche senza KV. A corrente e storica devono avere getter immutabili e
ricostruzione contata. Il **picco allocato e quello riservato completi
restano ignoti**. `cudaMemGetInfo` e zero spill ptxas non certificano
liveness integrata, allocator o assenza di trasferimenti di spill.

## Visite, traffico e lavoro ancora necessario

| Voce | Replay completo respinto | Variante per resti |
|---|---|---|
| Installazione W | 1.024 visite; upload esterno W 61.394.690.560 B distinto | Commitment ancora invariato |
| W per risposta, voci note | 26 range + 2 linear + 1.024 prima apertura = 1.052 | 29 range + 2 linear + 1 prima apertura = **32** |
| A corrente, voci note | 512 commit + 512 apertura + 26 range | 512 commit + 1 prima apertura + 26 range = **539** |
| Ogni vecchia A, prima apertura | 512 visite | 1 visita |
| W/A/KV totali, HBM totale | Non chiusi | Non chiusi; includere gli accessi dei getter A e di ogni ricostruzione |
| Esterno per visite W residente | Zero | Zero; nessuno spill ammesso |
| Trasporto esterno protocollo, input/output, installazione | Ledger distinto | Ledger distinto, nessun costo sottratto dalla risposta |

I 32 passaggi W noti della variante muovono 1.964.630.097.920 B di payload
W, esclusi temporanei. Non sono un totale HBM. Le 539 visite A sono
visite logiche; la loro generazione può leggere W/KV e rieseguire produttori.
Non si assume che A packed esista gratis nella candidata ammessa.

Ogni catena D34/D35 ha **12 oracoli dati**, oltre alle maschere. Il report
ora elenca tutti i domini e byte. Dopo il primo folding a 7 bit, il primo
switch W richiede 103.079.215.104 B encoded (4 colonne Fp3, 12 base),
A 51.539.607.552 B: anch'essi richiedono streaming. Lo stato folded W
iniziale costa da solo 6 GiB Fp3; A 3 GiB. Il `initialize_sumcheck` denso
con evaluations e pesi non diventa lecito grazie alla FFT. Vanno progettati
ricostruzione/retention di questi stati, maschere, sali e aperture, con
stesso terminale VOLE. Non moltiplicare erroneamente per tre le 128
colonne **base** del primo oracolo.

A ha 3.471 sorgenti e 2.328 produttori (fra cui 773 P0, 421 RMS, 892 RNE nel
census pertinente), 4.446 target correnti; W 775 e ogni vecchia A uno.
Le aperture sorgente sono 2/3/4 per risposta. I 526 alberi e 39 stream
privati del run completo sono un lifetime, non memoria simultanea.

### WHIR: lo stato successivo non sostituisce quello interrogato

Il [prover nativo](../../rust/third_party/p3-whir-c61/src/pcs/zk/prover/mod.rs) committa l'oracolo successivo e i mask/OOD prima delle
query all'oracolo precedente; gamma arriva dopo le righe aperte. Si può
fondere ricostruzione→hash sottoalbero→open-and-fold; non commitment con
query future, né aggiornamento del covettore con gamma ancora ignota.
Il folding ha kernel non banale: il successore da solo non determina le
righe Merkle precedenti. Non cambiare root o rivelare pad per evitarlo.

Il guard nativo `C62GpuSumcheckState::initialize` richiede 40N byte:
**1.374.389.534.720 / 687.194.767.360 B** per W/A. È un'ammissione densa
che fallisce chiusa, non un lower universale. Dopo fold7, evaluations+pesi
Fp3 occupano **12.884.901.888 / 6.442.450.944 B**, prima di cache/pad.
Non basta allentare il guard: serve un sumcheck/covettore streaming con
lavoro uniforme; q valutazioni eq per cella reintrodurrebbero qN. Dopo
fold9, sole values W/A costano 1.610.612.736 / 805.306.368 B; la retention
è valutabile più avanti, contando destinazioni e ultimo consumer.

La prima geometria esplicita senza retention S1 usa coset da 2^24 righe,
12 coordinate base e Q=64 W /32 A. Ogni coset ricostruisce la sorgente:
aggiunge **64 visite W e 32 di ciascuna A** al commitment del primo switch.
Una ulteriore ricostruzione S1 dopo query porta il subtotal a **97 visite
dirette W, 572 A corrente e 34 per vecchia A**. Non sono il totale: mancano
sumcheck, altri switch, maschere e letture W/KV dei getter. Anche OOD
ha challenge post-root: senza S1 retained il suo replay non si fonde
con le 64/32 scansioni pre-root. Le 97 visite
muovono 5.955.284.984.320 B di payload W; non tutto l'HBM. Il lower congiunto
sopra omette deliberatamente questi costi aggiuntivi positivi. Il piano
letterale per resti di tutti i 12 oracoli conta 3.152.737.468.416 butterfly W
e 1.593.688.457.216 per A prima della specializzazione payload/pad;
non mescolare questi totali con quelli specializzati dei primi oracoli.

Liveness proposta del primo switch W: coset 1.610.612.736 B, frontiera
3.221.225.472 B, twiddle 134.217.728 B, sali start/current 268.435.456 B,
pad 49.152 B e stack 800 B = **5.234.541.344 B**. Conservare una cache S1
h8 da 301.989.856 B finché S1 è stato interrogato, oltre alla cache iniziale
W/tre A da 188.743.552 B. Con reader/hash 256 MiB, getter 64 MiB, scratch
trie, output PCG, istogramma e cap proof, subtotal **6.195.259.192 B**,
margine **247.191.752 B**. Dopo rilascio coset/frontiera, l'apertura usa
il piano per resti, cache S1 e gli stessi slot: **5.775.778.832 B**,
margine **666.672.112 B**. Una cache S1 h6 con questo workspace completo
non entra: un piano che omette spettri/prodotto-tree non prova il picco.

Sono cap dei buffer nominati, non un picco completo: mancano maschere,
covettore/sumcheck, seed/OT e overhead allocator. Il commit A iniziale
rimane ancora più stretto: dei 115.235.048 B residui dopo cap proof,
getter+trie ne occupano 70.893.568, lasciando **44.341.480 B** per gli
altri stati. Nessun trasferimento esterno può supplire: spill vietato.

### PCG: righe reali, trie pubblico e costi separati

Le 3.814.605 / 3.826.014 / 3.826.329 righe base dello schedule fisso sommano
11.466.948, entro capacità 70.778.880. Nel formato nativo il prover conserva
`[u64;4]`, valore 8 B più tag Fp3 24 B: **32 B/riga**, totale bulk
**366.942.336 B**, non i precedenti 183.471.168 B. Il verifier ha 24 B/riga.
Il piano usa 4.096 righe/131.072 B: produrre, combinare ogni tre righe in
Auth/Key Fp3, consumare nel dominio previsto, azzerare. Poiché 4.096
non è divisibile per tre, conservare fino a due righe fra batch: carry
prover **64 B** (verifier 48 B), contato nei subtotal. Nessun pool bulk.

Il setup letterale cGGM mem-sublinear a due traversate richiede almeno
`2*675*(2^19-1)=707.787.450` valutazioni interne H per ruolo, più >=N
accumulazioni UH con N=353.894.400. Si paga una volta per run; fondere UH
con la seconda traversata dopo la challenge evita traffico separato, non
la prima traversata senza conservare le foglie. Il vecchio conteggio
`2N+209R=3.104.380.932` resta un **upper componente**, non un lower AES.
Non identificare la H cGGM Fp3/ROM selezionata con un generico albero
AES128-MMO; il backend B11 AES fornisce i seed. Costi H→AES/field, OT e
stati persistenti sono ancora ignoti.

Si può batchare la lista pubblica EA di ell=11 indici per riga. Con
u<=45.056 termini su 675 alberi di altezza 19, il trie condiviso visita
al più `sum(j=0..18,min(675*2^j,u))=626.397` nodi interni, contro 856.064
path-step indipendenti per batch: **26,83% di lavoro upper in meno**.
Con le code effettive: **583.385.798 / 585.121.123 / 585.174.648 H/ruolo**
per risposta, anziché 209R. Non sono lower temporali. Il refinement va
verificato separatamente per Acc e PuncAcc: memoization solo entro stesso
albero/blocco/label, correzioni private del ruolo punctured, ordine originale
degli output ripristinato. Indici/coefficienti vengono da EAGen pubblico,
mai da witness o Delta; nessuna correlazione riutilizzata tra sessioni.

Scratch proposto: due array di termini allineati 1.441.792 B, due
frontiere sparse Fp3 2.162.688 B e istogramma 180.224 B, totale extra
**3.784.704 B**, oltre output già contato. Seed/OT/off-path/correzioni non
sono implicitamente inclusi. Il controllo minimo è un trace bounded
Acc/PuncAcc equivalente al riferimento, contatori H/AES/field e vita di
ogni stato. Il bootstrap **61.841.290 B** rimane wire condizionale.

## Upper analitico e throughput minimo

L'upper completo richiesto ha la forma conservativa, senza overlap:

```
T_response <= sum_k [L_k_upper + sum_j work_kj/R_kj_min
                    + HBM_k/BW_k_min + external_k/BWext_k_min]
```

Le categorie k sono: inferenza; ricostruzione A/KV e producer/GKR;
range W; range A; linear W/A/vecchie A; PCS di tutti gli oracoli dati e
maschere; PCG/OT/MAC/FS; serializzazione/trasporto dipendente dalla
risposta; allocazione/launch/sincronizzazione/host. La somma di IO e
calcolo è qui prudenziale: ogni quantità va addebitata una volta; se si
usa un upper di kernel completo non riaggiungere il suo IO. Setup W e
bootstrap si riportano anche nei prefissi totali, senza nasconderli.

Per ottenere un numero finito mancano lavoro e service-rate floors
applicabili a diverse categorie; **l'upper di ammissione è quindi
+infinito, non 50 s e non una previsione di tempo infinito reale**.
Le soglie seguenti concedono tutti i 50 s a una sola voce e sono solo
necessarie; per un budget t_k usare `work/t_k`, con `sum(t_k)<=50`.

| Nucleo variante | Lavoro | Throughput minimo /50 s |
|---|---:|---:|
| Merge W | 740.982.521.855 | 14,820 Gmerge/s |
| Coefficienti W residenti, 18 mul/bucket | 201.326.556 bucket | 4,027 Mbucket/s |
| Fold W, H incluso | 1.006.637.247 scalari | 20,133 Mfold/s |
| Nucleo range W fattorizzato | 3.469.226.278.261 mul Fp3 | 69,385 Gmul/s |
| Nucleo range A fattorizzato | 1.571.622.485.383 mul Fp3 | 31,432 Gmul/s |
| Suffix-first W | 314.498.580.480 aggiornamenti | 6,290 Gaggiornamenti/s |
| Prima apertura W, payload e pad specializzati | 2.738.851.151.872 butterfly | 54,777 Gbutterfly/s |
| Primo commit A, FFT sola | 3.023.656.976.384 butterfly | 60,473 Gbutterfly/s |
| PCS complete, getter A/KV, PCG, inferenza, serializzazione | Parzialmente ignoti | Soglia completa non disponibile |

Le righe range nucleo includono merge e coefficienti; non sommarle.
Il commit A aggiunge 512*(A_live+128*1536) prodotti di scaling generico,
oltre a twiddle, hash e sali; non sparisce con l'apertura per resti.
Per le sole prime aperture specializzate servono almeno 78,673/104,648/
132,697 Gbutterfly/s se si concedono tutti i 50 s a questa voce. Per un
budget assegnato t, ogni soglia è work/t; 90 s resta solo un confronto.
Per PCG si divide per t l'upper del lavoro effettivamente selezionato per
il contratto di servizio, non lo si presenta come throughput necessario
universale. Mancando i costi completi non esiste ancora un'assegnazione
di t che certifichi la risposta.

## CUDA, harness e controlli ridotti

[`c71_fft_microbench.cu`](../../cuda/c71_fft_microbench.cu) implementa
trasposizione in-place a coppie di tile 32x32, FFT di riga shared,
twiddle+trasposizione, seconda FFT di riga e trasposizione naturale.
Non usa una seconda codeword. Array massimo componente 4 GiB più
32 MiB twiddle; transpose usa 16.896 B shared, row FFT <=16.384 B.
Input SplitMix64 seed `0xc701ff7025020001`; quick M256/batch8, completo
M2048/batch128. Il controllo GPU preliminare M64/batch2 copre anche tile
off-diagonal, prima delle allocazioni grandi. Non è stato eseguito.

Il [record statico su checkout pulito](../../benchmarks/results/c71-local-cuda-static-2026-09-13-ef2cdabc1afa.json)
fissa SHA `ef2cdabc1afabdb687e280092d0e07f8e40e30f0`,
archivi/toolchain, patch header, errori iniziali, log ptxas, dump SASS
del merge e controlli host dei binari CUDA. `git_dirty:false`,
`gpu_execution:false`, `credit:false`; nessun tempo GPU.

Range e FFT compilano localmente con nvcc **12.9.86**, `-O3 -std=c++17
-arch=sm_90 -Xptxas=-v`. ptxas: zero stack/spill in tutti i kernel;
range massimo 80 registri, FFT massimo 40. Non è una misura H100.
Toolchain temporaneo ARM64 SBSA dalle
[redistribuzioni NVIDIA 12.9.1](https://developer.download.nvidia.com/compute/cuda/redist/redistrib_12.9.1.json),
archivi verificati SHA-256. Il primo compile è fallito per le quattro
exception specification sinpi/cospi di glibc 2.41; la copia temporanea
header applica soltanto `noexcept(true)` a quelle quattro dichiarazioni
non usate. Conservare errore originale e hash prima/dopo; questa non è
una compilazione con toolkit intatto né il toolchain H100 di produzione.
Il problema corrisponde alla
[segnalazione NVIDIA](https://forums.developer.nvidia.com/t/error-exception-specification-is-incompatible-for-cospi-sinpi-cospif-sinpif-with-glibc-2-41/323591).

Controlli locali riproducibili, senza GPU e senza pesi reali:

```sh
ulimit -v 2097152
PYTHONDONTWRITEBYTECODE=1 timeout 60s pytest -q -p no:cacheprovider \
  tests/test_c71_streaming_screen.py tests/test_c71_range_microbench.py \
  tests/test_c71_query_remainder.py
PYTHONDONTWRITEBYTECODE=1 timeout 60s python3 scripts/run_c71_fft_microbench.py \
  --host-only --host-log2-m 3 --timeout-seconds 30
# Con CUDA devel disponibile; compila soltanto, non invoca --gpu:
timeout 60s nvcc -O3 -std=c++17 -arch=sm_90 -Xptxas=-v \
  cuda/c71_fft_microbench.cu -o /tmp/c71-fft-sm90
```

Gli harness [range](../../scripts/run_c71_range_microbench.py) e
[FFT](../../scripts/run_c71_fft_microbench.py) hanno input deterministici,
check CPU/GPU preliminare, metadata cloud obbligatori, controllo SHA/tree
prima e dopo il run, timeout e record append-only. Sono componenti;
l'input/harness della costruzione **integrata** non è ancora pronto.

## GO/NO-GO prima di qualsiasi spesa

| Gate | Controllo minimo successivo | Stato |
|---|---|---|
| Algebra/endpoint | Adapter piccolo nativo con righe, pad, sali, root, codec e MAC identici; rifiuto delle alterazioni | Identità finite passate, refinement aperto |
| CUDA | Compile/SASS; poi reader, inverse/remainder e pipeline hash rappresentativi con input piccolo | FFT ottimizzata e probe range compilati; reader e remainder CUDA mancanti |
| A/KV | Trace getter immutabile per tutte le ricette e O=0/150/300, conteggio ricostruzioni e dipendenze | Replay scalare escluso; getter esatto e slot 64 MiB da verificare |
| PCS completa | Tutti i 12 oracoli per catena, maschere, stati folded, source-uniformity e salt seek | Ancora aperto |
| PCG | Trace AES/cGGM a batch, seed/state/OT, no pool bulk; costi di entrambi i ruoli | Upper componente soltanto |
| Memoria | Ogni buffer vivo, arena totale, allocated/reserved globale <80 GB, assenza di spill | Buffer nominati compatibili nella variante, totale ignoto |
| Tempo | Somma completa <=50 s sotto contratti applicabili; ogni lower compatibile | Replay completo e getter scalare esclusi; alternativa senza upper finito |
| Riproduzione e spesa | Clean SHA pubblicata, harness/input integrati, immagine/deadline/prezzo fissati, autorizzazione nuova | Gate non raggiunto |

Non si propone RunPod per il replay già escluso né si usa un microbench
veloce per accreditare il resto. Il precedente comando/preventivo puramente
indicativo resta nella storia Git: con lo steering corrente non è una
proposta attiva. Preparare un comando provider istanziato e un preventivo
solo dopo che la costruzione completa resta plausibile entro 50 s e
l'harness integrato è pronto; nessuna autorizzazione di spesa è acquisita.
