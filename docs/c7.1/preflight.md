# C7.1 — preflight locale, 2026-09-18

**NO-GO per H100.** Lo screen dei costi dominanti respinge il getter che
rigenera tutta A con prodotti scalari a ogni visita: il solo commit A
impone >=135,257 s nelle condizioni esplicite sotto. Le specializzazioni
range/FFT/apertura per resti riducono il lavoro, ma il loro lower parziale
non esclude una costruzione diversa entro 65 s. Upper completo e picco
completo restano aperti. **90 s è una soglia di discussione del proprietario,
non una deroga autorizzata.** Il contratto vigente autorizzato è
`T_inference + T_proof_only <=65 s`. Nessun pod, spesa o esecuzione GPU.

I conti riproducibili sono in
[`integrated_resource_ledger`](../../scripts/c71_streaming_screen.py) e
[`c71_query_remainder.py`](../../scripts/c71_query_remainder.py), `credit:false`.
`null` significa ignoto; il corrispondente upper di tempo è **+infinito**.
**Il proprietario non richiede un upper H100 prima delle misure.** Il gate
pre-spesa è ora: costruzione completa e corretta su input ridotti, lavoro
senza voci ignote, picco pianificato completo con 256 MiB di margine e lower
congiunto <65 s; poi harness/input, SHA pulita, durata/costo e soglie per le
sole fasi a rate ignoto. La variante 1.024 replay è chiusa NO-GO; si procede
soltanto sui 512. Nessun gate qui concede l'autorizzazione alla spesa.
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

KV originale costa **901.120 B/token**, cioè
`4*(50*16*256+10*4*512)`. Il precedente 4.915.200 B/token era
l'incremento di **A attenzione** (`60*8192*10`) e non la cache K/V:
non usarlo come misura della cache. Questa correzione non riduce A. Prefisso accettato:
0 / 135.168.000 / 270.336.000 B; con coda pendente da 150 token:
135.168.000 / 270.336.000 / 405.504.000 B. Proposta: un solo buffer
KV modello persistente prenotato per 450 token, append nella coda
inutilizzata, promozione del cursore solo dopo accettazione. Questa
classificazione vale solo per KV originale, non per witness o workspace;
la coda pendente è sempre contata nel picco globale e non sovrascrive
il prefisso. Se l'implementazione usa staging temporaneo, conta nell'arena.

W + riserva KV450 + arena = **68.242.645.504 B**; rimangono
**11.757.354.496 B** sotto 80 GB per runtime/context e altri residenti
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

Sono cap dei buffer nominati, non un picco completo: maschere e stati
ora censiti nel [trace integrato](#trace-della-risposta-e-budget-separati)
si aggiungono ai precedenti subtotali. Per i margini correnti usare quel
ledger, che include anche metadata e pad/seed iniziali. Restano da
verificare i workspace nativi e l'assenza di spill.

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
+infinito, non 65 s e non una previsione di tempo infinito reale**.
Le soglie seguenti concedono tutti i 65 s a una sola voce e sono solo
necessarie; per un budget t_k usare `work/t_k`, con `sum(t_k)<=65`.

| Nucleo variante | Lavoro | Throughput minimo /65 s |
|---|---:|---:|
| Merge W | 740.982.521.855 | 11,400 Gmerge/s |
| Coefficienti W residenti, 18 mul/bucket | 201.326.556 bucket | 3,097 Mbucket/s |
| Fold W, H incluso | 1.006.637.247 scalari | 15,487 Mfold/s |
| Nucleo range W fattorizzato | 3.469.226.278.261 mul Fp3 | 53,373 Gmul/s |
| Nucleo range A fattorizzato | 1.571.622.485.383 mul Fp3 | 24,179 Gmul/s |
| Suffix-first W | 314.498.580.480 aggiornamenti | 4,838 Gaggiornamenti/s |
| Prima apertura W, payload e pad specializzati | 2.738.851.151.872 butterfly | 42,136 Gbutterfly/s |
| Primo commit A, FFT sola | 3.023.656.976.384 butterfly | 46,518 Gbutterfly/s |
| PCS complete, getter A/KV, PCG, inferenza, serializzazione | Parzialmente ignoti | Soglia completa non disponibile |

Le righe range nucleo includono merge e coefficienti; non sommarle.
Il commit A aggiunge 512*(A_live+128*1536) prodotti di scaling generico,
nella geometria precedente, oltre a twiddle, hash e sali; non sparisce con l'apertura per resti.
Per le sole prime aperture specializzate servono almeno 60,518/80,498/
102,075 Gbutterfly/s se si concedono tutti i 65 s a questa voce. Per un
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

Il [nuovo record statico dei costi dominanti](../../benchmarks/results/c71-dominant-static-2026-09-13-ca29dbd3cc8c.json)
è raccolto su SHA pulita `ca29dbd3cc8c`: compile sm_90 di entrambi i file,
15 test ridotti, controlli host dei binari CUDA, SASS dei probe range e
della FFT ottimizzata, hash e ledger analitico. Conferma 1.183/231
istruzioni per merge6/leaf-pair e 77 nel ciclo butterfly; zero stack/spill,
range max 80 registri, FFT max 40 (row 32). Conserva per riferimento
l'evidenza precedente e la patch temporanea del toolkit. È `credit:false`,
`git_dirty:false`, `gpu_execution:false`: nessun tempo GPU o upper completo.

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

## Trace della risposta e budget separati

Il [ledger eseguibile](../../scripts/c71_response_trace.py) compone tre
trace locali: [A/KV](../../scripts/c71_getter_trace.py),
[WHIR](../../scripts/c71_whir_trace.py) e [PCG](../../scripts/c71_pcg_trace.py).
Sono `credit:false`, senza witness canonico, GPU o nuovi run di protocollo.
Gli eventi nominano allocazioni, ultimo consumer e rilascio; i buffer
condivisi W/A compaiono una volta. Le sorgenti hanno ID, nome, shape e
codec compilati nel medesimo ordine del nativo, verificati sul census.

La partizione richiesta è esplicita:

```
T_inference      = una corretta generazione nativa del provider
T_proof_only     = getter/replay + producer/GKR + range + linear + PCS
                   + PCG/MAC + serializzazione/trasporto + attese/verifica
T_response_total = T_inference + T_proof_only
```

Le verifiche/attese necessarie per completare la risposta appartengono
alla fase proof; nessuna fase di rete o final acceptance viene assegnata
implicitamente a zero. Il protocollo FS non introduce round-trip online
per challenge del verifier. L'installazione globale si riporta separatamente;
il setup fresco di sessione è un sottocomponente separato, addebitato una
volta al PCG della prima prova e a ogni prefisso completo, senza ammortizzarlo.
Un replay dell'inferenza per ricostruire
A, anche se identico a quello del provider, è **interamente proof_only**.
Manca la baseline nativa del provider: attualmente tutti e tre gli upper
sono ignoti (`null`), upper di ammissione +infinito. Non si usa il budget
come input della funzione che somma gli upper.

Questa è una **ripartizione di obiettivi** da sottoporre ai contratti di
servizio, con la stessa somma per O=0/150/300, non una previsione:

| Fase | Budget s |
|---|---:|
| Inferenza nativa originale | 3,0 |
| Getter e ricostruzioni durante la prova | 14,0 |
| Relazioni producer e GKR | 1,0 |
| Range W e A | 18,0 |
| Linear W/A e history | 1,0 |
| Commit iniziale A | 7,0 |
| Prime aperture W e tutte A | 15,2 |
| WHIR successivo, maschere e terminale | 3,0 |
| PCG/MAC, setup fresco nella prima prova | 2,0 |
| Serializzazione/trasporto | 0,3 |
| Host, sincronizzazioni e interazioni verifier | 0,5 |
| **Proof only / totale** | **62,0 / 65,0** |

Il ledger genera le soglie work/budget, **non service-rate floors**:
FFT commit A >=431,95 Gbutterfly/s per la sola voce; le aperture chiedono
258,79 / 344,24 / 436,50 Gbutterfly/s. PCG conta nel piano trie gli
upper 583,386 / 585,121 / 585,175 milioni H per ruolo, più
83,921 / 84,172 / 84,179 milioni chiamate SHAKE EAGen. Alla prima prova
si aggiungono 707,787 milioni H/ruolo del setup a due traversate, hash
universale e seed/guard/OT, con costi ancora parziali. Non confondere
un upper di lavoro con un lower di lavoro necessario per ogni algoritmo.
Le soglie PCG per secondo dividono questi conteggi per il nuovo budget
di 2 s; quelle del nucleo WHIR successivo per 3 s.
Il budget getter è ora 14 s per la geometria precedente; la variante con
più margine richiede già 17,627–18,795 s nel suo lower condizionale. La
ripartizione resta provvisoria e non costituisce uno schedule ammesso.
Per getter le soglie si riferiscono al piano di ricostruzione dichiarato;
non sono il costo dell'inferenza originale.

### A/KV: routing controllato e fusione per producer

Il trace canonico ricostruisce **3.471 sorgenti e 36.171 tessere byte** per
contesto, con gli esatti 13.154.672.538 / 14.334.320.538 / 15.513.968.538 B.
Il reference getter verifica snapshot/root/Gamma, intervalli e larghezza
signed; emette byte biased agli indirizzi originali. Il test ridotto
confronta indipendentemente il complemento a due e rifiuta uno snapshot
successivo sostituito. Non equivale al confronto bit-per-bit del digest
nativo completo o a un teorema di NoPeek.

Le tessere ordinate richiedono **4.913.944.241 / 5.356.312.241 /
5.798.680.241 word fetch**, contro 3.646.354.972 / 4.014.994.972 /
4.383.634.972 word distinte: i byte 4+2 degli i48 sono separati. Il commit
può ricevere contributi sparsi all'indice originale, producendo raw, byte
e RNE insieme; non cambia ordine di hash/transcript, che segue dopo la FFT.
Il range ordinato e Horner high-to-low non ereditano questa fusione.
Il loro piano di dependency cut resta un controllo richiesto.

Il trace per producer segue **1.568 nodi** della topologia originale,
con shape aggregate sui 150 token fissi. KV storico è immutabile; il replay
non effettua una seconda append. I dot QK/PV sono contati separatamente
dai learned matrix; EXP30, RMS, RNE, RoPE, istogrammi, affini e argmax
hanno unità di lavoro separate. Il commit assorbe un istogramma completo
prima di riusarne il buffer: un solo slot da 262.140 B al posto di 121
istogrammi trattenuti. I tensori nominati hanno picco **52.690.940 B**;
restano da verificare dentro lo slot 64 MiB kernel workspace, packing
INT8/correzioni e callback nativo. Gli upper degli accessi agli operandi
W/X del piano tiled16x256 sono logici; non sono HBM misurato. Nessuna
cache efficace, coalescenza o inferenza gratis è presunta.

### WHIR e PCG: stati prima mancanti

WHIR censisce tutti i **12 oracoli dati, 23 gruppi/40 maschere**, le
controparti fresche, OOD, query e base case. La cache di un nuovo root
coesiste con coset/frontiera/twiddle durante la costruzione. Cache e pad
iniziali persistono fino al teardown del fixed run; si bruciano soltanto
stati e correlazioni del tentativo, non i segreti necessari a riaprire
W e A accettate.

Il caller `c71_matrix.rs` apre un **singleton** dopo il reducer lineare:
`claim_count*N=N` non viola la regola uniforme. I primi sette round possono
usare una contrazione su **128 Fp3 =3.072 B**, una scansione sorgente e
127 pair-terms; il test finito confronta tutti i coefficienti con il denso.
Il guard nativo 40N continua a fallire: il nuovo schema non è ancora il suo
adapter. Nei round successivi il covettore è una Eq più <=**5.643 Pow**.
Per la somma `w_j=sum a_i*x_i^j`, la serie è P(X)/Q(X), Q(0)=1.
La candidata a blocchi genera questi coefficienti con inverse e FFT fisse,
aggiorna le ampiezze tra blocchi e preserva il fold **MSB**:
`a_i <- a_i*(1-r+r*x_i^(N/2))`, con x_i invariata. Il test confronta
blocchi e fold con le somme dense; non usa l'identità even/odd errata.

I 22 round successivi costano nel nucleo **23.613.929.984 /
11.802.770.816 butterfly Fp3** W/A, ossia **70.841.789.952 /
35.408.312.448 butterfly base**. OOD è in Fp3: non si possono trattare
Q/inverso come polinomi base. Scratch nominato **507.445.224 B**, con
allocazione durante i due round e rilascio prima del commit seguente.
Il precompute ha ora un reference con upper finito: Q richiede <=66.598.686
mul/add Fp3; i numeratori dei blocchi <=785.296.296 / 647.395.740;
la ricorrenza inversa <=14.539.536.648 / 12.633.300.552. Sono contati
separatamente gli spettri inversi. Non è credito al product-tree/Newton
ottimizzato: il termine numero-blocchi per lavoro del numeratore deve
ancora rispettare il coefficiente sorgente indipendente da q/h. Decoder,
Eq, adapter e resto del runtime WHIR rimangono aperti.
Il commit coset letterale resta invece
non uniforme al crescere della sorgente; non è un encoder ammesso.

PCG ora ha reference SHAKE **H** ed **EAGen** con codec domain-separated,
otto tentativi per campionamento e fail-closed. Il supporto EAGen contiene
11 indici distinti uniformi e coefficienti Fp non nulli; il bound di
esaurimento è una frazione esatta nel report. È una decisione di codec
locale da collegare alla stessa coin pubblica, **non un nuovo messaggio**,
un port di B11 o un trasferimento automatico del teorema.
Il prover GPU è il receiver punctured: stato allineato **348.372 B**;
il verifier conserva Delta e **32.496 B** canonici. Le frontiere/batch
sono ulteriori, così come le materializzazioni Fp3/Fp6 del setup. Seed,
counter, carry e burn sono contati. EAGen aggiunge **252.272.856 RO** per
ruolo nel run; non sono AES calls o byte HBM. Sono contati anche i figli
destri cGGM, Acc/PuncAcc, mul/accumuli EA, hash universale e compressione
Fp6→Fp3. PuncAcc del prover ha upper **4.793.184.264 add Fp3** nel run;
EA aggiunge 126.136.428 mul scalari e altrettanti accumuli per ruolo.
Workspace OT/Fp6 e costi
completi dei due ruoli restano il controllo nativo minimo.

### Picco integrato e screen della ricostruzione

Senza retention dei folded state, includendo le candidate sumcheck, le
visite note sono **169 W dirette**, A corrente **634**, ciascuna vecchia A
**96**. I dependency replay del getter ordinato e altro lavoro dei producer
restano ulteriori. Traffico diretto W: **10.375.702.704.640 B**, distinto
dal W letto dal getter A. Le richieste logiche KV del piano querywise
sono 12,854 / 27,655 / 44,403 TB: non un lower né il totale HBM.

| O | Arena nominata con tutti gli slot proposti, B | Residuo, B |
|---:|---:|---:|
| 0 | 6.324.532.620 | 117.918.324 |
| 150 | 6.363.854.220 | 78.596.724 |
| 300 | 6.403.175.820 | 39.275.124 |

Il picco è il commit A corrente; include root/pad/seed iniziali realmente
vivi, getter 64 MiB, reader/hash 256 MiB, metadata 128 MiB, cap proof
130 MB, istogramma W e stato/batch/trie PCG del prover. Gli slot non
provano i workspace nativi che devono entrarvi. W+KV450+arena riservati
sono **68.242.645.504 B**, residuo globale **11.757.354.496 B** prima di
Gamma/runtime/context. Allocato e riservato **completi** restano ignoti.
Setup ha un ledger separato: un picco risposta non ne certifica il fit.

Lo screen a quattro dot-product int8 usa un ceiling **condizionale e
generoso di 2,2 POPS densi**, superiore alla targa densa ricavata dalla
[tabella NVIDIA H100](https://www.nvidia.com/en-eu/data-center/h100/)
(3.958 TOPS con sparsity, che non è concessa a questi prodotti densi).
Non è un throughput minimo, né una conversione di TOPS in Fp3.
Per il piano seriale senza retention, soltanto learned-matrix replay più
il precedente lower range/FFT/aperture danno **43,012 / 47,934 / 53,091 s**,
prima di inferenza, PCG e resto. Questo respingeva il piano alla terza
risposta con 50 s; con il nuovo limite a 65 s non basta per respingerlo.
Questo giustifica cercare retention/fusioni A; non ulteriore tuning range/FFT.

La candidata retention A ora arriva **fino al base case**, per ciascuna
catena corrente o storica con la propria prova fresca. Dopo la prima query
si rigenera S1 una volta e lo conserva immutabile. Il commit S2 usa coset
2^23; la query S1 usa blocchi 2^17 e cache h8. Solo dopo la query si fa
fold in place, fence e rilascio della coda. Si ripete l'ordine
commit-successore → query-predecessore → fold per S2…S11, mantenendo
maschere, pad e segreti fino al loro ultimo consumer.

Le visite originali diventano **574 A corrente e 36 per vecchia A**;
W rimane a 169 visite dirette. Per catena si aggiungono **80 scansioni di
stati conservati**, 74.893.479.936 B letti e 4.294.966.272 B scritti di
payload, più **2.027.246.624 interpolazioni Fp3**. I commitment dei successori
scrivono 68.720.787.456 B encoded: non sono letture A né trasferimenti
esterni. Il report distingue anche XOF dei sali e operazioni dei resti;
non accredita questi subtotali come HBM completo.

| O | Rigenerazioni A nominate | Lower parziale con retention, s | Picco della sola catena retention con slot, B |
|---:|---:|---:|---:|
| 0 | 574 | 42,038 | 6.194.747.340 |
| 150 | 610 | 45,986 | 6.234.068.940 |
| 300 | 646 | 50,170 | 6.273.390.540 |

Il massimo integrato resta il commit A corrente della tabella precedente;
range e linear riusano l'arena in fasi separate, senza C anticipata durante
il range. La retention evita 60/120/180 rigenerazioni A. Il lower della terza
risposta superava il vecchio limite a 50 s; **non esclude i 65 s autorizzati**.
Inferenza e lavoro retained restano aggiuntivi. La soglia
50,170 s è un lower condizionale, non una previsione o un upper. Restano
da chiudere margine fisico, lavoro completo e controlli nativi; questo checkpoint non giustifica una spesa H100.

## GO/NO-GO prima di qualsiasi spesa

| Gate | Controllo minimo successivo | Stato |
|---|---|---|
| Algebra/endpoint | Adapter piccolo nativo con righe, pad, sali, root, codec e MAC identici; rifiuto delle alterazioni | Identità finite passate, refinement aperto |
| CUDA | Compile/SASS; poi reader, inverse/remainder e pipeline hash rappresentativi con input piccolo | FFT ottimizzata e probe range compilati; reader e remainder CUDA mancanti |
| A/KV | Trace getter immutabile per tutte le ricette e O=0/150/300, conteggio ricostruzioni e dipendenze | DAG condiviso e finestre censiti; getter numerico e slot 64 MiB ancora da verificare |
| PCS completa | Tutti i 12 oracoli per catena, maschere, stati folded, source-uniformity e salt seek | Ancora aperto |
| PCG | Trace AES/cGGM a batch, seed/state/OT, no pool bulk; costi di entrambi i ruoli | Upper componente soltanto |
| Memoria | Ogni buffer vivo, arena totale, allocated/reserved globale <80 GB, assenza di spill | Buffer nominati compatibili nella variante, totale ignoto |
| Tempo | Somma completa <=65 s sotto contratti applicabili; ogni lower compatibile | Replay completo e getter scalare esclusi; alternativa senza upper finito |
| Riproduzione e spesa | Clean SHA pubblicata, harness/input integrati, immagine/deadline/prezzo fissati, autorizzazione nuova | Gate non raggiunto |

Non si propone RunPod per il replay già escluso né si usa un microbench
veloce per accreditare il resto. Il precedente comando/preventivo puramente
indicativo resta nella storia Git: con lo steering corrente non è una
proposta attiva. Preparare un comando provider istanziato e un preventivo
solo dopo che la costruzione completa resta plausibile entro 65 s e
l'harness integrato è pronto; nessuna autorizzazione di spesa è acquisita.

## Picco con margine operativo: contratto a 65 s

Il [piano degli indirizzi](../../scripts/c71_arena_plan.py) adotta **256 MiB
(268.435.456 B) inutilizzati dentro l'arena** e 1 GiB di margine globale.
Sono criteri operativi locali più prudenti del solo fit, non memoria
aggiuntiva: il cap resta 6.442.450.944 B e il globale sotto 80 GB.
Il [checker C++](../../cuda/c71_arena_preflight.cpp) verifica offset allineati
256 B, assenza di sovrapposizioni, cap con margine e rilascio soltanto con
fence dichiarata. I suoi 512 descrittori occupano 12.288 B nel test nativo.
Non alloca 6 GiB, non usa CUDA e non dimostra che un kernel abbia completato
la fence: è il controllo nativo del piano per un singolo slab preallocato.

Per liberare spazio senza ridurre slot ipotetici, la candidata dimezza il
coset iniziale A da 2^22 a **2^21** e quello S2 da 2^23 a **2^22**. Conserva
root/cache/pad, proof buffer, PCG, getter e metadata. L'allocatore first-fit
mantiene gli indirizzi dei buffer vivi; il fold in place accorcia lo stesso
span dopo la query e la fence. Range e linear riusano lo slab in fasi
separate. Lo spazio liberato non viene dichiarato workspace già verificato.

| O | Massimo indirizzo occupato, B | Coda libera nell'arena, B | Rigenerazioni A nominate |
|---:|---:|---:|---:|
| 0 | 5.983.782.912 | 458.668.032 | 1.086 |
| 150 | 6.023.104.512 | 419.346.432 | 1.122 |
| 300 | 6.062.426.112 | 380.024.832 | 1.158 |

Il massimo è il primo switch W; riservato totale dello slab resta 6 GiB.
Rimangono 10.683.612.672 B globali per residenti ancora non verificati,
**dopo** W, KV450, slab e margine globale da 1 GiB. Non è un'autorizzazione
ad allocare witness o temporanei fuori arena. La prima codifica A ora
richiede 1.024 rigenerazioni; gli stati retained aggiungono 96 passaggi e
126.433.087.488 B logici letti per catena. Il lower condizionale del solo
replay learned-matrix è **17,627 / 18,211 / 18,795 s**. Non riutilizzare
il precedente lower FFT completo: il coset cambia kernel/layout.

La FFT di lunghezza 2^21 può usare scatter iniziale per parità, due FFT
quadrate da 2^20 e merge finale in place. Il test finito confronta questa
identità con DFT in ordine naturale. **L'adapter CUDA dispari non è ancora
implementato**: niente credito di tempo o root nativa dal test algebrico.
La FFT quadrata esistente usa soltanto values e twiddle globali; i suoi
transpose/row kernel usano shared memory, già distinta dall'HBM. Il trace
non trasforma questo controllo nel workspace completo della PCS.

L'audit dei percorsi nativi distingue tre incompatibilità/obblighi:

- Estendere letteralmente `Snapshot::values: Vec<Vec<i64>>` alle shape
  canoniche richiede almeno 29.170.839.776 / 32.119.959.776 /
  35.069.079.776 B, prima di byte packing o PCS: **NO-GO per quel layout**.
  Il percorso piccolo non è un getter canonico streaming.
- Il getter ordinato con una rigenerazione completa per tessera ha un
  buffer di uscita massimo 32 MiB, ma 36.171 rigenerazioni per passaggio:
  **>=587,085 s per un solo passaggio**, sotto lo stesso ceiling INT8 e
  modello quattro GEMM. **NO-GO per questa fallback**; occorrono dependency
  cut condivisi, senza assumere gratuitamente il costo sourcewise.
- WHIR nativo alloca evaluations e pesi densi; PCG seed/OT/Fp6, producer
  GKR, inferenza e allocator/context completi restano da collegare. Il
  checker degli offset non assorbe quei costi negli slot per definizione.

Il picco fisico completo e l'upper temporale completo restano ignoti per
O=0/150/300. Questi NO-GO riguardano costruzioni precise; nessun lower
universale respinge tutte le candidate a 65 s. Il gate H100 resta chiuso:
prima serve un getter ordinato praticabile e il censimento dei workspace
nativi dentro gli slot. Non c'è ancora un microbenchmark completo minimo
pronto a validare tale percorso; non si propone un costo di pod speculativo.

## DAG condiviso, getter ordinato e riuso del reader

Il [trace canonico](../../scripts/c71_ordered_getter.py) riusa i producer e
le ricette esistenti: 3.471 sorgenti, 36.171 tessere, 1.568 nodi aggregati.
Il taglio inter-layer conserva embedding scalato e uscite dei 60 layer:
61 × 150 × 5376 × 2 = **98.380.800 B**, per una sola A originale. Costruirlo
costa un replay nella prova; non si prende credito dall'inferenza del provider.
Ogni finestra esegue una volta la chiusura delle dipendenze necessarie.
Un output in checkpoint non sostituisce il raw del medesimo producer:
se serve il raw, si esegue il producer e si emettono insieme i suoi output.
Il checkpoint resta immutabile e legato a `(O, root, Gamma)`; non si promuove
KV durante il replay. Il callback ridotto verifica la disciplina del DAG,
non realizza da solo i MAC originali o il preparatore numerico canonico.

Il range usa una finestra byte da 2 GiB. Il kernel deve vedere gruppi
`[tail][prefisso già folded][u della nuova finestra Gram][sottoalbero]`.
I fold nativi accoppiano le due metà: la prima coordinata è MSB, come in
`c71_matrix::fold`, non l'ordine little-endian di altri helper diagnostici.
Il trace conta esattamente le intersezioni fra tessere e queste finestre;
il test finito confronta i gruppi raccolti con i fold densi originali.
Le 26 passate comprendono il tree iniziale, le finestre Gram e la retention
finale di ogni livello. Nessuna sfida futura serve a stabilire gli indirizzi.
Il suffisso esterno di padding è zero pubblico; uno zero interno di una
sorgente signed deve invece essere emesso con il suo encoding biased originale.

La query iniziale di ciascuna A usa finestre da 256 MiB. Ogni colonna
consuma i suoi blocchi high-to-low dalla finestra già prodotta, anche se
la finestra copre due colonne. I 35 passaggi S1 non-query (singleton,
32 commit coset, OOD e rigenerazione S1) possono accumulare mappe lineari
sourcewise nello stato destinazione. Il test fold/coset verifica questa
identità su dati finiti. **Non si fondono passaggi attraverso root, OOD
o altre barriere FS.** Dopo la rigenerazione S1 e la fence si liberano
i checkpoint; S1/S2 e tutte le catene successive conservano la liveness
già censita. Prima del W opening non rimane un checkpoint A.

| O | Istanze producer nelle 26 passate range | MAC learned-matrix range | Istanze producer query A originale | MAC learned-matrix query |
|---:|---:|---:|---:|---:|
| 0 | 313.469 | 904.403.877.888.000 | 42.291 | 109.468.503.244.800 |
| 150 | 312.464 | 899.342.283.571.200 | 42.590 | 109.262.890.598.400 |
| 300 | 316.187 | 912.629.484.748.800 | 42.767 | 107.695.610.265.600 |

Le query storiche si sommano: a O=300 si pagano tutte e tre le righe query.
Questi sono conteggi esatti di istanze nella schedule descritta, non il
numero di istruzioni del futuro kernel. Attention MAC causali sono separati
dall'upper rettangolare del vecchio producer trace. Le richieste KV storiche
range, senza credito di riuso GQA, sono 0 / 10.602.086.400.000 /
21.422.407.680.000 B. Le richieste W del modello 16×256 sono
121.006.313.845.248 / 120.350.032.823.808 / 122.128.348.466.688 B:
**non sono transazioni HBM né lower di banda**. Il report distingue il
lower dei pesi learned disgiunti obbligatori, con 256 MiB di cache concessi
a ogni finestra/generazione. I 169 passaggi W diretti della prova restano
separati dalle letture W dentro il getter e dall'inferenza; il totale
completo W/KV/HBM, inclusi producer GKR e backend, non è ancora chiuso.

### Esito temporale e minima alternativa strutturale

Con 1.024 replay del commit A, il solo getter ha lower condizionale
compute INT8 **20,940 / 21,936 / 22,993 s** e banda pesi
**23,502 / 24,617 / 25,793 s**. I ceiling sono 2,2 POPS densi, quattro
dot INT8 esatti per MAC i16, HBM 3,35 TB/s e cache al più 256 MiB per
finestra/generazione. Non sono service floor. Si usa il massimo fra
banda e compute nella stessa fase, non la loro somma.
La FFT 2^21, se eseguita come un solo batch di 256 metà 2^20 con cinque
passaggi globali e merge separato, richiede almeno altri 6,892 s di banda
nel modello dichiarato. Getter + merge range + prime aperture + FFT danno
**56,227 / 60,704 / 65,481 s**. Il terzo caso è **NO-GO per questa schedule
seriale** prima di inferenza, PCG e altro lavoro positivo. Questo bound non
si trasferisce a FFT con batch minori, fusione o un altro metodo getter.

La modifica minima censita riusa il reader/hash slot da 256 MiB **solo
durante il commit iniziale A scatter**. Lo slot viene collocato alla coda
delle riserve persistenti, rilasciato dopo fence e ripristinato dopo il
commit: nessuna root/seed viva cambia indirizzo. Permette il coset 2^22
con la FFT quadrata già compilata, **512 replay**, senza cambiare polinomio,
pad, sali o root. L'hash deve leggere la riga completa e scrivere i quattro
word del digest nelle quattro celle della medesima riga ormai consumata;
righe diverse non si sovrascrivono. Il test degli indirizzi dimostra solo
questa proprietà indipendente dall'hash. **Il codec salted nativo, il salt
seek e lo scratch register/shared/local del kernel restano da collegare**:
non si assume che eliminare la prenotazione elimini il lavoro del reader.

| O | Picco commit A nominato, B | Picco integrato nominato, B | Coda arena libera, B | Lower getter compute / banda, s | Lower congiunto parziale, s |
|---:|---:|---:|---:|---:|---:|
| 0 | 6.056.097.536 | 6.087.369.472 | 355.081.472 | 12,630 / 14,160 | 46,882 |
| 150 | 6.095.419.136 | 6.126.691.072 | 315.759.872 | 13,626 / 15,275 | 51,360 |
| 300 | 6.134.740.736 | 6.166.012.672 | 276.438.272 | 14,682 / 16,451 | 56,136 |

Il picco range include core conservativo W, finestra A 2 GiB e checkpoint,
oltre a tutti gli slot/root/cache già nominati. Il checker C++ verifica
allineamento 256 B, non sovrapposizione, fence dichiarate e ripristino del
reader. **8.002.816 B** è lo spazio ulteriore al margine richiesto di
268.435.456 B nel caso peggiore. Nel getter slot da 64 MiB restano
14.417.924 B dopo i 52.690.940 B di tensori; packing/correzioni devono
rientrarvi o essere aggiunti al piano. L'arena riservata è sempre
6.442.450.944 B. Il picco fisico allocato/riservato completo rimane ignoto.

Il ledger candidato assegna i seguenti **budget di ammissione, non upper**:

| Fase | Budget, s |
|---|---:|
| Inferenza originale provider (`T_inference`) | 1,5 |
| Getter/replay A/KV della prova | 17,0 |
| Relazioni producer GKR | 0,8 |
| Range W/A | 17,9 |
| Linear W/A/history | 0,8 |
| Commit iniziale A: FFT/hash, escluso getter già contato | 7,0 |
| Prime aperture W e tutte A | 15,2 |
| WHIR restante/maschere/endpoint | 2,0 |
| PCG/MAC, setup fresco nella prima risposta | 2,0 |
| Serializzazione e trasporto | 0,3 |
| Verifier/host/attese | 0,5 |
| `T_proof_only` | **63,5** |
| `T_response_total` | **65,0** |

Il report ricalcola le soglie parziali per merge, coefficienti, fold, FFT,
PCS e PCG con questi budget. A O=300 il getter richiede già almeno
3,242 TB/s di letture obbligatorie dei pesi per rientrare nei 17 s,
prima del resto del traffico. È un controllo di severità, non una previsione
di prestazione. Per tutti gli O i tre **upper** temporali restano `null`;
l'upper completo di tempo è +infinito perché mancano contratti; il nuovo
gate pre-misura non esige ancora questo upper.
Non si modifica il requisito totale a 65 s e non si presume overlap.

Il controllo minimo successivo è locale: producer numerici equivalenti
ai byte originali, hash salted in place e sourcewise WHIR con dominio,
codec e sali identici; poi censimento di scratch reale PCG/OT/Fp6, producer
GKR e provider. Sono obblighi di costruzione, non soli service-rate ignoti.
Quindi **NO-GO per una proposta H100 ora**: nessun comando/pod/costo attivo.
Un microbenchmark isolato sarà pertinente quando una fase concreta e il
suo workspace sono chiusi e rimane da misurarne il service-rate.

Riproduzione locale dei trace (metadati, nessuna GPU; ogni processo limitato
separatamente a 60 s e 2 GiB), dalla SHA pulita indicata nell'evidence:

```bash
ulimit -v 2097152
for C71_O in 0 150 300; do
  PYTHONDONTWRITEBYTECODE=1 timeout 60 .venv/bin/python scripts/c71_ordered_getter.py --old "$C71_O" > "/tmp/c71-ordered-$C71_O.json"
done
PYTHONDONTWRITEBYTECODE=1 timeout 60 .venv/bin/python scripts/c71_ordered_getter.py --combine /tmp/c71-ordered-0.json /tmp/c71-ordered-150.json /tmp/c71-ordered-300.json > /tmp/c71-ordered-combined.json
```


## Getter numerico e hash nativo ridotti

Il [getter Rust](../../rust/volta-pcs/src/c71_matrix/gemma/native/ordered.rs)
riusa lo stesso `evaluate_row` del preparatore per tutti gli operatori
ridotti. Compila la chiusura delle dipendenze delle sorgenti richieste,
calcola ogni producer una volta per finestra e libera gli input dopo
l'ultimo consumer. Raw, istogrammi e byte biased vengono emessi prima del
rilascio. Le due cut del profilo ridotto sono i16 effimeri; solo K/V i16,
token e identità originali sopravvivono fra risposte. I cut non si accumulano
con la storia. La forma canonica conserva ancora i 61 cut già censiti,
senza acquisire credito numerico da questa prova ridotta.

Il test confronta tutti i byte del dominio D12, padding esterno incluso,
contro il `Snapshot::prepare` originale per O=0/2/4 e quattro larghezze di
finestra (1/17/128/1.024). Lo Snapshot denso esiste soltanto come riferimento
del test; non è allocato dal getter. Il controllo respinge contesto/root dei
cut e bound alterati. Nessuna correlazione, seed PCS o FS entra nel replay.
L'API è interna: non autorizza l'import di token/cut/KV dal prover avversario.
`source_root` è metadata fidato del test, non viene ricalcolata dal replay:
il binding al lifecycle accettato e alle root storiche originali resta
un obbligo dell'adapter, non è scaricato dal confronto byte.

| O ridotto | Byte A live | Righe producer, finestre da 1.024 B | Letture scalar W / A / KV | Picco heap nominato, B |
|---:|---:|---:|---:|---:|
| 0 | 942 | 85 | 90 / 240 / 0 | 1.296 |
| 2 | 1.006 | 85 | 90 / 268 / 16 | 1.376 |
| 4 | 1.070 | 159 | 176 / 562 / 64 | 1.520 |

Questi conti sono per un passaggio ordinato ridotto; escludono la costruzione
delle cut, workspace interni degli operatori e metadati dell'allocator.
Non sono operazioni complete, HBM fisica, picco completo o misure canoniche.
Restano da collegare dimensioni pinned/GQA/padding/selezione delle righe,
gather Gram e consumer del prover; la correttezza ridotta non chiude questi
obblighi. I MAC endpoint e il transcript esistenti non sono modificati.

L'[hash native CPU](../../rust/volta-pcs/src/c71_matrix/b12/streaming.rs)
legge una riga del coset column-major e scrive i quattro word digest nelle
prime quattro celle consumate della stessa riga. I digest restano word raw,
mai ridotti modulo p. Il test confronta le foglie e la root con la MMCS
nativa per larghezze 4/7/128/384, comprese le soglie multi-chunk BLAKE3;
verifica anche root consecutive, salt seek in ordine inverso e rigetti
forzati del vero sampler Fp. Il codec resta little-endian canonico,
`leaf/v1`/`node/v1` e quattro sali, senza nuova serializzazione.

Il test strided usa foglie `c+Q*j`, prescan naturale del sampler, start/current
offset effettivi e una frontier `j × log2(Q)`. Alla fine dell'ultimo coset
le radici per j riusano le celle digest e si riducono alla root originale.
Gli offset di subtree sono registrati nello stesso scan e il seek produce
gli stessi sali delle aperture native. Non si assume assenza di rigetti:
un caso forzato consuma 48 byte per quattro sali, anziché 32.
Gli offset sono già nei 16L byte del piano, la frontier nei 32L log2(Q);
non si aggiunge un array di tutti i sali o digest. `size_of` CPU rileva
1.920 B per Hasher e 128 B per PrivateRng, esclusi stack dei callee; non
sono stime dello scratch CUDA né una chiusura del picco fisico.

Il [ledger hash](../../scripts/c71_whir_trace.py) è integrato nel workspace
commit e nel [ledger risposta](../../scripts/c71_ordered_getter.py).
Per il commit iniziale A, in ogni contesto canonico:

| Lavoro/traffico logico | Quantità |
|---|---:|
| Foglie / nodi interni | 2.147.483.648 / 2.147.483.647 |
| Letture payload foglie | 2.199.023.255.552 B |
| Scritture digest foglie | 68.719.476.736 B |
| Letture / scritture digest con frontier | 137.573.171.136 / 68.853.694.432 B |
| Compressioni BLAKE3 foglie + nodi, escluso XOF | 42.949.672.958 |
| Candidati XOF minimi prescan + replay | 137.438.953.472 B |
| Letture/scritture logiche cursori | 34.359.738.368 B |
| Scrittura start e copia current | 100.663.296 B |
| Scrittura offset subtree trattenuti | 4.194.304 B |

Il sampler mantiene il cap nativo di 2^40 byte per stream e Stop su
esaurimento. I byte candidati effettivi dipendono dai rigetti; il ledger
riporta separatamente minimo, cap e lavoro deterministico, senza inventare
un conteggio esatto indipendente dalle coin. Le transazioni HBM e lo scratch
CUDA restano da censire. Il passaggio foglie separato dalla FFT, concedendo
256 MiB di cache a ognuno dei 512 coset e 3,35 TB/s, aggiunge un lower
condizionale di **0,615398 s**. Non si sommano IO e compute dello stesso
kernel. I lower congiunti **ancora parziali** diventano
**47,497618 / 51,975184 / 56,751469 s**. Il budget commit da 7 s richiede,
fra l'altro, 314,146 GB/s di payload leaf e 6,136 miliardi di compressioni
BLAKE3/s; sono condizioni necessarie parziali, non sufficienti con la FFT.

Il confronto sourcewise WHIR/codec ridotto è ora chiuso sotto. Restano
aperti il port canonico, workspace nativi e allocator/fence, PCG/OT/Fp6,
producer GKR e inferenza. I valori
`T_inference`, `T_proof_only`, `T_response_total` restano distinti e ignoti;
replay e autenticazione stanno interamente nella prova. Il margine 256 MiB
è conservato dal piano nominato, non ancora dimostrato per il runtime.
**NO-GO per proporre una spesa ora**, nessun NO-GO universale dei 512 replay.


### Confine nativo WHIR e workspace da collegare

L'audit delle API individua un percorso locale preciso, senza cambiare il
transcript. `ZkWhirInitialMessage::Resident` e
[`ZkWhirOracleCommitter`](../../rust/third_party/p3-whir-c61/src/pcs/zk/prover/mod.rs)
accettano già un
[`ResidualSumcheckProver`](../../rust/third_party/p3-sumcheck-c61/src/strategy.rs)
custom. Il singleton iniziale può contrarre il suffisso in 128 accumulatori
prima dei sette round adattivi. Lo stato successivo deve conservare Eq/Pow,
claim, sfide già fissate e i workspace sourcewise censiti. Il solo handle
`Resident` non impedisce le seguenti allocazioni:

| Confine | Condizione necessaria per restare sourcewise | Fallback attuale da evitare |
|---|---|---|
| Commit successivo | `commit_extension_from_sumcheck` restituisce `Some` | `evals()` materializza il messaggio |
| OOD | `evaluate_padded_ood_from_sumcheck` restituisce `Some` | nuova `evals()` prima dell'OOD |
| Claim nuovo | `accumulate_round_claim_from_sumcheck` restituisce `true` | messaggio e `weight_delta` densi |
| Base case | `evals()` e `weights()` finali reali | qui il dominio è solo 32 Fp3 per vettore |

Il secondo confine è di ownership:
[`HidingWhirProverData`](../../rust/third_party/p3-whir-c61/src/pcs/zk/prover/data.rs)
richiede `MT::ProverData<DenseMatrix<F>>`. L'MMCS hiding installata conserva
`MerkleTree<HorizontalPair<M, RowMajorMatrix<F>>>`, cioè matrice, sali e tutti
i livelli digest. `open_and_fold` apre direttamente quel tipo. La sola
root corretta del nuovo hash non converte tale ownership nella cache alta
più replay contabilizzata dal piano. Per esempio il primo codeword A da
2.199.023.255.552 B rende già NO-GO il lift di **questo backend denso**;
non è un lower contro un backend sourcewise.

Il wrapper MMCS da solo non conserva il contratto `get_matrices -> Vec<&M>`
senza trattenere una matrice. È stato quindi aggiunto il confine di replay
al motore WHIR: handle privato opaco, commit/apertura e rilascio dopo
l'ultimo consumer. I chiamanti residenti esistenti restano supportati;
Commitment/MultiProof, verifier e codec non cambiano. Le maschere piccole
conservano il backend nativo già censito. Le aperture intermediate
propagano gli errori; il callback base-case nativo non è fallibile e un
errore termina con panic, da tradurre in `Stop` prima della promozione
quando si collega il lifecycle completo.

Anche la mappa delle coin va confrontata nella costruzione composta:
`HidingWhirProver::new` crea l'extension MMCS tramite `mmcs.clone()`, che
consuma un seed di 32 byte dal parent. Seed/cursore di ciascuna root vanno
quindi derivati dall'ordine nativo dei fork e commit; il confronto hash
isolato non autorizza a iniziare tutti i sali dall'offset zero.

Nel picco effettivo devono comparire simultaneamente i due root handle
predecessore/successore fino alle query, pad/seed e offset originali,
512 righe aperte/sali/multiproof, fresh randomness e OOD, tutte le maschere
trattenute (messaggi, coin, covettori 2.048 Fp3 e Merkle data), vettori della
prova e buffer codec, descrittori Eq/Pow, scratch razionale, stato base-case
e chiusura OpeningMac. Gli slot del piano sono riserve: questo audit non
attribuisce loro automaticamente l'ownership del backend reale.
Il controllo ridotto D10 con 512 query include ora `ObservedMmcs`, che
lega aperture/sali/frontiere al FS C7.1, e confronta tutti i round,
root/aperture/sali, codec (**2.289.176 B**), transcript, target affine e
chiusura base-case, con verifica nativa finale. Rifiuta i fallback densi
prima del dominio finale di al più 64 elementi. Il test separato dei round
copre anche la contrazione iniziale a sette sfide. Lo stato sourcewise
è un riferimento CPU limitato a D16: la valutazione diretta Eq/Pow e il
replay Horner non sono il kernel razionale/remainder del ledger canonico.

L'albero di replay conserva getter fissato, snapshot XOF, offset effettivi
e cache alta. Il `cut` è esplicito e deve essere una potenza di due fra Q
e H. Le root Q-leaf dell'ultimo coset vengono ridotte nelle celle consumate:
nessuna copia `32*L` (**134.217.728 B** a L=2^22). Il pad iniziale è condiviso
tramite Arc. I test piccoli confrontano fork, avanzamento del cursore,
query duplicate e ordine del multiproof. I contatori della cache e dello
scratch sono byte nominati; non certificano allocator o picco GPU completo.

Il [riferimento PCG](../../rust/volta-pcg/src/c71_ea_lpn.rs) confronta H ed
EAGen con vettori del codec Python. H usa tre slot XOF distinti da 64 B,
un massimo di otto candidati per componente e 192 B complessivi, cioè due
permutazioni SHAKE256; i candidati effettivamente verificati restano
variabili. EAGen usa due XOF per termine. Il controllo esaustivo a profondità
1–7 verifica `Acc(omega)-PuncAcc(omega)=Delta*[omega>=alpha]`. Non è un
setup OT: il fixture conosce root e Delta. Il confine OT/Seed6 seguente è
un controllo separato; trie batch, consumo MAC e picco completo con
producer/inferenza restano aperti.

Questi risultati mantengono `credit:false`, lower parziali invariati e gate
pre-spesa NO-GO. Non sostituiscono i trace canonici O=0/150/300 né chiudono
il margine fisico di 256 MiB.

Il getter numerico è collegato alla catena con la root A originale nei tre
contesti ridotti O=0/2/4. Conserva una finestra di 128 byte, cut i16 e KV
originali; Snapshot/A completi restano soltanto nel riferimento indipendente.
S1 viene fissato al primo fold ma materializzato soltanto dopo le query
alla root A e il rilascio del predecessore. Un unico slot condiviso conserva
gli stessi valori per lo stato e l'oracolo S1 già impegnato. Non anticipare
questa allocazione al commit S1: violerebbe la liveness del piano canonico.
Il test dei round verifica il getter congelato prima/dopo la materializzazione.
Il confronto numerico ridotto copre root, codec, FS e chiusura con
`verify_pcs` sul MAC ideale fissato prima delle sfide. Un endpoint MAC
alterato rifiuta; non c’è una nuova autenticazione dopo le sfide.
La coda in-place S1→S2, i domini canonici e il binding al lifecycle accettato
restano da collegare. Il riferimento CPU non accredita i passaggi del kernel
razionale o il picco fisico canonico.

Il confine [Seed6](../../rust/volta-pcg/src/c71_seed6.rs) controlla codec K6
canonico, sei maschere e relazione completa prima della compressione E-lineare;
una key compressa zero rifiuta. Vettori indipendenti e alterazioni di ogni
limb verificano il rifiuto prima del campionamento alpha. Il motore MR19
esistente ora ammette internamente conteggio e domini separati: il controllo
reale a 384 OT restituisce il seed scelto per tutte le coordinate, con
127.488 B di payload e 27 B di framing. Le vecchie suite mantengono i domini
precedenti. Sono componenti test-only: COPE Seed6, handshake/lifetime, secondo
seed con ruoli fisici opposti, guard e consumo MAC composto restano aperti.
I conteggi esatti di check/compressione e i payload nominati sono nel
[ledger PCG](../../scripts/c71_pcg_trace.py); non comprendono allocator,
stack crittografico e temporanei del backend, né chiudono il picco.

Il nuovo censimento di `evaluate_row` aggrega le operazioni scalari dirette,
le letture LUT e le capacità effettive dei risultati nel trace del getter.
Le chiamate RMS/RNE/affine/divide restano esplicite: il flag di completezza
aritmetica è falso finché i loro interni non sono censiti. Sono operazioni
a livello sorgente, non istruzioni macchina o traffico HBM; i contatori
non trasformano il preparatore ridotto nel producer canonico. La costruzione
S1 usa `Arc<Vec<E>>` per spostare l'header senza una copia del corpo; la
scansione di materializzazione legge A in ordine crescente.
