# C7.1 — preflight locale, 2026-09-19

**Traguardo locale attivo (2026-09-26): pronto per il minimo esperimento
H100.** Il gate pre-spesa sotto è il criterio di achieved; un upper H100
misurato entro 65 s non è richiesto per chiudere questo goal locale.
Il lavoro continua senza GPU o spesa. Margine invariato: si interviene
su una coesistenza di buffer che sfora concretamente, senza riservare
preventivamente ulteriore margine.

**NO-GO per H100 del main-cell scalare implementato.** Il solo EXP30 a
O=300 richiede ≥67,103981 s alle condizioni hardware dichiarate, prima
di qualsiasi altro costo. La prova ridotta integrata passa, ma questo
backend non può rispettare il contratto `T_inference + T_proof_only <=65 s`.
Il precedente getter che rigenera A con prodotti scalari era già escluso
(≥135,257 s per il solo commit nelle sue condizioni). Una costruzione con
lavoro aritmetico o backend diversi resta da dimostrare; upper e picco
fisico completi non vengono attribuiti ai controlli ridotti. **90 s è una
soglia di discussione, non una deroga autorizzata.** Nessun pod, spesa o
esecuzione GPU.

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

Il nuovo [lower del main-cell scalare fuso](#no-go-del-main-cell-scalare-fuso)
è decisivo già senza completare i costi mancanti: EXP30 O=300 da solo
richiede ≥67,103981 s nel backend compilato. Questo backend è NO-GO;
non si propone un run H100 per cercare di recuperare il tetto di 65 s.
Lo [screen successivo di due alternative](#due-alternative-strutturali-exp30)
riapre soltanto una candidata locale a transcript invariato: aggregazione
dei pattern Boolean nei primi quattro round. Il lower di 67,10 s non si
trasferisce al lavoro rimosso; non c'è ancora un lower/upper completo nuovo.

## Lower di banda e calcolo separati

Il lavoro locale segue il gate integrato del 2026-09-19: una prova ridotta
positiva con getter ordinato, lookup streaming, GKR sourcewise e WHIR,
transcript e MAC originali, seguita dal ledger congiunto e dal minimo
kernel fuso rappresentativo. Lookup/GKR/capacity accounting restano
congelati salvo errori da almeno 16 MiB di picco o 0,5 s; nuovi dettagli
ABI non sono un gate autonomo. I contatori del riferimento scalare non
sostituiscono il lavoro della schedule canonica a 512 replay.


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

Il raccordo cGGM mem-sublinear a due traversate conta
`2*675*(2^19-2)=707.786.100` valutazioni H sender e
`2*675*(2^19-19-1)=707.761.800` receiver, più N prodotti/accumuli UH
con N=353.894.400 e maschere. Il primo split non usa H. Il vecchio
707.787.450 era un upper, non un lower per ruolo; il ledger ora usa
il massimo dei due ruoli come upper comune. Si paga una volta per run; fondere UH
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
si aggiungono al più 707,787 milioni H/ruolo del setup a due traversate, hash
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

La retention A arriva **fino al base case**, per ciascuna catena corrente
o storica con la propria prova fresca. Dopo la prima query si rigenera S1
una volta. L'ordine resta commit-successore → query-predecessore → rilascio
handle → fold per S2…S11. Il riferimento CPU conserva **l'intera capacità
S1 di 3.221.225.472 B** fino all'ultimo consumer: `Vec::truncate` riduce la
lunghezza, non la capacità. Non si accredita più il rilascio della coda.

Il vecchio cap S3 2^24, conservando questa capacità, porta a O=300 il live
allineato a **6.602.051.328 B** e l'high-water di indirizzi a
**6.682.796.800 B**: NO-GO per quel layout. Il cap minimo qui selezionato
è **S2 2^22, S3 e successori al massimo 2^23**. S1 resta 2^24. Il cambio
aggiunge due letture logiche S2, **1.610.612.736 B per apertura A**, senza
nuove scansioni originali A/W. Ogni catena usa 76 replay per i commit dati,
98 letture di stati conservati e **128.043.700.224 B** di payload letto;
le interpolazioni pianificate diventano **3.688.191.008**. Le scritture
encoded restano 68.720.787.456 B, quelle XOF dei sali 22.906.929.152 B.
Questi sono conteggi della schedule, non istruzioni o transazioni HBM.

| O | High-water indirizzi apertura A, B | Massimo integrato nominato, B | Coda libera integrata, B |
|---:|---:|---:|---:|
| 0 | 5.945.991.936 | 6.087.512.576 | 354.938.368 |
| 150 | 5.985.316.864 | 6.126.837.504 | 315.613.440 |
| 300 | 6.024.638.464 | 6.166.159.104 | 276.291.840 |

Il massimo integrato resta il range. Il margine minimo nominato supera
256 MiB di soli 7.856.384 B: allocator, fence GPU e workspace non ancora
rifiniti non possono essere omessi. Le visite originali restano 574 per
A corrente e 36 per ogni A storica, più il lavoro degli stati conservati.

Le FFT dei commit S1…S11 hanno log-coset **24,22,23,23,21,19,17,15,13,13,13**.
Per i log dispari il producer deve scrivere `[pari][dispari]`; due FFT
quadrate five-pass sono seguite da un merge radix-2 in-place. Il merge
costa un'ulteriore lettura e scrittura del payload, non zero. Per catena
il ledger conta **101.156.536.320 butterfly**, 8.590.098.432 prodotti di
cross-twiddle e 268.517.376 butterfly nel merge (già inclusi nel totale).
I valori richiedono 347.900.215.296 B letti e altrettanti scritti; i twiddle
877.973.078.016 B di accessi logici. Inizializzazione dei twiddle, scatter,
hash e maschere restano separati. La tabella completa n*8 è già nello slot;
non c'è un buffer globale aggiuntivo per lo split. Il microbench copre
l'identità CPU e il codice device; il collegamento allo scatter PCS resta
un gate. Non è traffico HBM misurato né un upper temporale.

Il lower parziale corrente 47,498/51,975/56,751 s non include questi costi
successivi e resta soltanto un lower parziale, non un upper o un gate GO.
Non esclude i 65 s, ma non giustifica una spesa H100.

## GO/NO-GO prima di qualsiasi spesa

| Gate | Controllo minimo successivo | Stato |
|---|---|---|
| Algebra/endpoint | Adapter piccolo nativo con righe, pad, sali, root, codec e MAC identici; rifiuto delle alterazioni | Identità finite passate, refinement aperto |
| CUDA | Compile/SASS; poi reader, inverse/remainder e pipeline hash rappresentativi con input piccolo | FFT ottimizzata e probe range compilati; reader e remainder CUDA mancanti |
| A/KV | Trace getter immutabile per tutte le ricette e O=0/150/300, conteggio ricostruzioni e dipendenze | DAG condiviso e finestre censiti; getter numerico e slot 64 MiB ancora da verificare |
| PCS completa | Tutti i 12 oracoli per catena, maschere, stati folded, source-uniformity e salt seek | Ancora aperto |
| PCG | Trace AES/cGGM a batch, seed/state/OT, no pool bulk; costi di entrambi i ruoli | Upper componente soltanto |
| Memoria | Ogni buffer vivo, arena totale, allocated/reserved globale <80 GB, assenza di spill | Buffer nominati compatibili nella variante, totale ignoto |
| Tempo prima delle misure | Lavoro completo, lower congiunto compatibile con 65 s, service-rate ignoti isolati; nessun upper H100 richiesto | Replay completo e getter scalare esclusi; ledger integrato candidato aperto |
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
| 0 | 6.056.240.640 | 6.087.512.576 | 354.938.368 | 12,630 / 14,160 | 46,882 |
| 150 | 6.095.565.568 | 6.126.837.504 | 315.613.440 | 13,626 / 15,275 | 51,360 |
| 300 | 6.134.887.168 | 6.166.159.104 | 276.291.840 | 14,682 / 16,451 | 56,136 |

Il picco range include core conservativo W, finestra A 2 GiB e checkpoint,
oltre a tutti gli slot/root/cache già nominati. Il checker C++ verifica
allineamento 256 B, non sovrapposizione, fence dichiarate e ripristino del
reader. **7.856.384 B** è lo spazio ulteriore al margine richiesto di
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
Il passaggio in-place S1→S2 e successivi è ora collegato al rilascio
dell’oracolo precedente: il tree viene distrutto prima di rilasciare la lease.
La lease nasce solo dopo un commit riuscito; duplicati, prefissi troppo lunghi,
getter obsoleti e promozioni senza avanzamento sono respinti. Il getter
successore restituisce gli stessi valori prima/dopo il fold; la capacità S1
resta integralmente allocata. La sorgente originale viene rimossa dal backend
dopo la validazione e dal fallback dopo la materializzazione S1. I domini
canonici, il lifecycle accettato, il kernel razionale e il picco fisico
restano da collegare; il controllo CPU non li accredita.

Il confine [Seed6](../../rust/volta-pcg/src/c71_seed6.rs) verifica codec K6,
sei maschere, check completo e compressione E-lineare nonzero. È ora collegato
al percorso OT/AES ridotto descritto nella sezione seguente; il record
precedente resta evidenza dei soli componenti che allora eseguiva.

Il nuovo censimento di `evaluate_row` aggrega le operazioni scalari dirette,
le letture LUT e le capacità effettive dei risultati nel trace del getter.
Le chiamate RMS/RNE/affine/divide restano esplicite: il flag di completezza
aritmetica è falso finché i loro interni non sono censiti. Sono operazioni
a livello sorgente, non istruzioni macchina o traffico HBM; i contatori
non trasformano il preparatore ridotto nel producer canonico. La costruzione
S1 usa uno slot `RwLock` condiviso con le lease degli oracoli, senza copia
del corpo; la scansione di materializzazione legge A in ordine crescente.
Il lock delimita il riferimento CPU: non è una fence GPU né prova di rate.


## RMS: checkpoint originale e coefficienti GKR a memoria limitata

Il port denso è NO-GO per memoria: 347.937.024 celle RMS vive richiedono
N=2^29; i soli frame padded da 12 B occupano tutti i **6.442.450.944 B**.
Le assegnazioni `Option<usize>` aggiungerebbero 8.589.934.592 B. Questo
esclude quel backend, non il predicato o ogni prover streaming.

Il checkpoint compatto conserva i byte originali P/Y e S48 una volta per
riga, legato alla stessa `Sources` per lifetime. Comprende 314.145.024 celle
weighted, 33.792.000 unweighted e 576.149 statistiche: **2.023.495.038 B**
di payload e 16.840 B di descrittori. Il test nativo confronta tutti i frame
vivi/padded con il getter originale e propaga gli errori del reader.
Non conserva A/Snapshot completi. Il piano lo costruisce dopo root A/P0,
conserva i cut anche per le statistiche/X originali; li rilascia dopo
l'ultimo consumer numerico e P/S/Y dopo l'obbligo byte RMS,
prima di RNE/range. Riusa serialmente lo slot range da 2 GiB.
Con LUT e coefficienti dell'endpoint byte, i picchi vivi nominati sono
2.845.020.928 / 2.884.342.528 / 2.923.664.128 B; i massimi degli indirizzi
first-fit sono 2.943.302.400 / 2.982.624.000 / 3.021.945.600 B.
Non aumentano i massimi nominati del piano integrato.
Le capacità dei Vec sono censite; allocator e reader, insieme al replay Booleano limitato,
restano da collegare al picco fisico, senza assorbimenti impliciti negli slot.

Il nuovo motore dei coefficienti conserva tre righe Fp3, due vettori di
selettori e P flag pubblici: `(3W+2P)*24+P` B. Confronta i quattro
coefficienti con il riferimento denso dopo ogni sfida MSB, compresi And,
Xor, Copy e padding. Il replay Booleano selezionato riusa input/current/next nel medesimo prover
e li libera prima della LUT byte; capacità e puntatori sono verificati su
ogni profondità dopo la riserva iniziale. Usa la stessa validazione e gli stessi
operatori del riferimento, conserva solo livello corrente/successivo e
confronta ogni livello di circuiti weighted/unweighted reali. Un secondo
controllo collega tale replay al motore dei coefficienti dopo sfide MSB.
Il prover collega ora questi coefficienti alle riduzioni degli indici, al
controllo prodotti e all'endpoint byte originale. `Assignments::Lookup`
sostituisce il Vec da 8.589.934.592 B; il suo ABI misurato è 24 B,
contro 16 B per ogni `Option<usize>`. Il binding usa chunk da 4.096 B:
assorbe N byte nel fixture a cinque programmi (v1), 2N se i programmi
superano 255 (v2), senza cambiare frame o coin. Il caller costruisce
`CompactFrames` una sola volta dopo statistiche/prodotti. I test ridotti
confrontano l'intera prova serializzata, digest FS, punto e Auth con il
riferimento denso; il verifier non può conservare Eq(N) o P*N.
Salta i getter delle celle dummy. Il selettore usa una sola assegnazione
pubblica per cella; il salto dei programmi dipende dalla presenza pubblica,
mai da witness o cancellazioni in Fp3. Somma prima `weight_gate*f_gate`
nel programma, poi applica il selettore comune. Copy elimina i termini
quadratici e Xor raddoppia per addizione. Root, transcript e MAC non cambiano.

Il [censimento](../../scripts/c71_gkr_screen.py) confronta Python e Rust
su circuiti e supporti pubblici MSB, senza allocare N celle. Per il fixture
RMS a scale zero (cinque programmi, 98 livelli), le coppie gate/cella
passano da 214.231.894.583.618 a **85.128.509.507.906**. Il nucleo
fattorizzato conta **377.460.232.230.821 moltiplicazioni Fp3**, prima dei
fold, replay, adapter, FS e MAC. Sono conteggi dell'algoritmo specificato,
non un lower hardware o il profilo reale calibrato. Sono censiti anche i
ratio EXP30 a O=0/150/300. Le fusioni non danno credito al port canonico.
Il ledger della risposta integra RMS ed EXP30 per O=0/150/300, derivando
la geometria dai record nativi immutabili e ricalcolando le fold attive.
Il solo nucleo coefficienti combinato conta 386.961.541.320.376 /
405.831.540.624.554 / 424.701.435.131.804 prodotti Fp3; le maschere Boolean
sono 1.292.872.328.352.000 / 1.449.092.941.632.000 /
1.602.554.893.632.000. Getter, Eq, fold e coefficienti rimangono categorie
separate. Le soglie dividono il lavoro noto per il budget producer di
0,8 s: sono condizioni parziali da soddisfare, non service-rate o lower
hardware. Anche range/commit/aperture leggono i budget correnti dalla
stessa tabella del report, senza denominatori storici hardcoded.

Il replay scalare del fixture RMS richiede **988.837.022.208 callback**
per i livelli Booleani e **48.047.958.035.255.808 gate Booleani**;
le **1.218.388.473.792.000** moltiplicazioni per bit delle righe sono ora
maschere dei limb canonici, senza saltare addizioni o getter. Restano
988.837.022.208 prodotti Fp3 per i selettori, 1.219.377.310.814.208 addizioni
prima dei terminali e 121.240 interpolazioni terminali. Il census distingue
mask, prodotti, addizioni e sub terminali; il caso N=1 conta il replay
senza attribuirgli fold di celle. Questi costi sono aggiuntivi al nucleo
coefficienti. Sono operazioni sorgente della reference, non istruzioni o lower hardware.
I contatori runtime separano replay, capacità dei Vec, getter e coefficienti;
indice, autenticazione, codec e workspace complessivo non sono ancora chiusi.

L'endpoint byte denso è separatamente NO-GO: a cell_bits=29 e 16 lane,
il bottom occupa 105.553.116.266.496 B e l'albero 210.693.915.672.576 B.
La variante a getter usa una LUT pubblica di 511 nodi per byte/lane:
**100.466.688 B**, più **98.304 B** di coefficienti. Coesistono con il
checkpoint originale fino all'ultimo consumer; il piano li rilascia insieme
prima di range. Nessuna Eq o matrice child proporzionale al dominio è
necessaria per la rigenerazione MSB. Per gli otto livelli D33..D40 la
reference ora legge i quattro figli insieme: **87.686.052.315.136 richieste
al getter byte**, inclusa la contrazione terminale, per
350.744.209.260.544 valori scalari. I pesi Eq dei prefissi vengono aggiornati
solo sui bit cambiati dal riporto binario, nell'ordine MSB originale. Non
usa divisioni o salti quando una sfida/peso vale 0 o 1. Condivide i pesi
fra i quattro figli: il conteggio Eq scende da 7.032.424.831.646.836 a
**346.363.342.617.732 prodotti Fp3** (-95,07%), comprese le Eq analitiche.
Restano 350.744.209.260.544 prodotti/addizioni per i valori, senza credito
di riduzione di quelle operazioni. Il buffer dei pesi ha al massimo 984 B
nel caso RMS, 1.024 B allineati nel piano; coesiste con entrambi i punti.
È allocato una sola volta e riusato: il test verifica stabilità di puntatore
e capacità, oltre all'uguaglianza dei valori.
I test verificano sfide non base, 0/1, ogni prefisso/suffisso fino a sei bit
e byte/FS/MAC/PCS originali. `byte_source_trace` distingue questi costi, ma
esclude ancora MAC/FS, coefficienti pubblici, getter originale e allocator.
Le richieste ripetute alla LUT non sono automaticamente transazioni HBM.
La schedule canonica richiede specializzazione/fusione e un conteggio
proprio; non eredita il lower parziale precedente come lower completo.

Il vecchio screen delle prime sei coordinate dentro parole contigue usa
LSB-first; il transcript nativo fissa invece prima le coordinate MSB.
Non trasferire quei risparmi: servono un gather dimostrato e lo stesso
supporto pubblico. Il packing Booleano delle ultime sei coordinate resta
valutabile, contando i replay e i fold effettivi.

I kernel CUDA `c71_gkr_{and,xor,copy}_gate` compilano per sm_90 e hanno
controllo algebrico CPU su Fp3 non base. Sono probe separati di polinomi
weighted, con SASS e registri censibili; non un kernel GKR fuso completo.
I loro lower condizionali valgono solo per la schedule che esegue proprio
quei kernel, incluse le letture/scritture per gate. Non moltiplicare il
costo di un probe per prodotti inlined, né dichiarare NO-GO del motore
fuso da quei lower. Il controllo minimo successivo è replay Booleano
limitato, fold MSB e accumulo nel kernel integrato, con stessi coefficienti,
scratch e conteggio di istruzioni. Nessun microbenchmark H100 è ammesso
finché i gate di costruzione restano aperti.


## Seed6 reale streaming e workspace

L'[adapter sperimentale](../../rust/volta-pcg/src/c71_seed6/real.rs) collega
handshake `C71S6v02`, direction 0/1, MR19 384, COPE AES-256, check K6 e
compressione. Ogni correzione usa un buffer da 3.072 B; ogni sfida 48 B.
Il verifier riceve tutte le correzioni canoniche prima di inviare le sfide,
verifica K6 prima di campionare alpha e rifiuta la chiave compressa zero.
I seed OT e il contesto vengono rilasciati dopo COPE; check e mask si
cancellano prima della compressione. La capacità delle sei righe sacrificate
rimane allocata dopo `truncate`: il ledger la conta.

I test n=1/n=3 usano ruoli separati, due direzioni e socket locali; verificano
ogni MAC restituito e wire da **149.611 / 155.851 B**, incluso il seal. Il replay
di transcript privati alterati controlla correzione non canonica, Z alterato
e troncamento senza alpha. I [vettori OpenSSL/SHAKE indipendenti](../../scripts/c71_seed6_aes_kat.py)
verificano AES ai bordi dei cammini. La catena ridotta ora usa entrambi
i seed sigillati, guard, cGGM, coin e F_EQ; non il lifecycle completo.

Il [ledger](../../scripts/c71_pcg_trace.py) conta AES, sampler, MR19, check,
compressione, traffico logico e capacità per fase; non spaccia le letture
sorgente per traffico HBM. Corregge un'omissione: 15.528 è il solo seed
Dory; il principale con F_EQ contiene **17.553** righe, l'inverso **2.025**.
Ogni ruolo comprime quindi 19.579 elementi includendo la sua Delta. I due
byte direction-bound delle handshake aggiungono 2 B per seed allo screen:
bootstrap condizionale **61.841.366 B**, primo corpo parziale **126.894.610 B**,
inclusi i 27 B del framing F_EQ/coin e i successivi 45 B guard/split.
Il seal da 40 B per seed è ora implementato ed era già incluso nel budget.

I Vec dei punti MR19 hanno ora capacità preallocata esatta, senza crescita.
Sull'ABI CPU osservata (Point=216 B, Scalar=72 B), il massimo dei corpi Vec
MR19 è **266.496 B prover / 245.376 B verifier**, più il contesto da 240 B.
Sul seed principale la compressione prover conserva **1.404.576 B** di
corpi Vec, prima di stack/allocator/trasporto. Il piano arena include entrambi
i seed seriali, i ruoli invertiti e l'output del primo ancora vivo durante
il secondo; non ne rilascia gli output prima del consumer esterno ancora
mancante. Queste fasi non alzano il massimo complessivo nominato.

Restano espliciti stack crittografico/spill del compilatore, allocator,
trasporto, audit, burn durevole e FS globale. Il raccordo locale guard→cGGM→F_EQ
è descritto sotto. `puncture` è soltanto l'oracolo del riferimento:
nessun ruolo reale possiede tutti i suoi input. Non dà credito al bootstrap
composto, né chiude il picco fisico o il lower temporale congiunto. Restano
`T_inference`, `T_proof_only` e `T_response_total <= 65 s`, senza overlap.

Il primo split del riferimento è stato corretto rispetto alla
[Fig. 3 Dory](../../sota/2025-1660-dory-streaming-vole.md): il sender deve
ricevere `k` indipendente e offset, con figli `(k, offset-k)`, non
`(H(offset), offset-H(offset))`. Solo i livelli successivi usano H.
Il vecchio test restava un'identità additiva valida per l'albero hash-root,
ma non trasferiva le coin del setup distribuito selezionato. Ora `acc` e
l'oracolo `puncture` ricevono entrambi gli input; il test a profondità 1–7
confronta ogni prefisso con le foglie dense e ogni cammino punctured,
e controlla esattamente h−1 chiamate H per cammino sender. A h=1 non
si chiama H. Il conteggio prudente h dello screen resta un upper, non
si rivendica un risparmio di tempo H100. Il raccordo role-separated ora
usa lo stesso primo split e le coin native sotto; transcript globale e
lifecycle restano da collegare.
Il [record 42f0814](../../benchmarks/results/c71-cggm-first-split-2026-09-26-42f08149164e.json)
registra i quattro controlli nativi su SHA pulita, senza credito composto.


## Guard originale: consumer nativo

Il [consumer Seed6](../../rust/volta-pcg/src/c71_seed6/guard.rs) usa la
[stessa algebra](../../rust/volta-mac/src/c7_fp3.rs) ora condivisa dal range.
Il wrapper range conserva fase 0x600, sorteggio e record 0x45 nello stesso
ordine. Seed6 conserva tag/key originali e nega soltanto Delta, come il
pool nativo esistente. I test ridotti controllano cammini binari, beta zero,
gamma non binario, correzioni riordinate, proof alterata, codec e troncamento.
Un test collega il consumer a nove righe generate dagli OT/AES reali.

Per t=675,h=19 la ricetta usa 15.528 righe Dory: beta/path per blocco,
tre maschere split per blocco e le tre righe globali 15.525–15.527.
Queste ultime vengono cancellate dopo il check; split e ulteriori 2.025
righe F_EQ restano vivi. La sfida viene fissata in un oggetto distinto
prima dell'ingresso della proof. Solo la verifica positiva restituisce
`GuardAccepted`, ora consumato dal producer c a ruoli separati.
Il raccordo reale usa ora `prove_bound`/`challenge_bound`: SHAKE256 del
dominio guard, `/challenge/` e prefisso congelato, con il sampler Fp3
condiviso (otto candidati per limb, 192 B). Il prefisso comprende il binding
sigillato v02 e tutte le correzioni/righe prima della sfida. Nessun lambda
entra dal caller in questo percorso. I callback prefissati restano nei
test algebrici; il codec locale non chiude il transcript globale o il burn.
Il KAT Python/Rust verifica i 72 B assorbiti e il valore; prefisso/proof
alterati vengono respinti. Lo slot temporaneo pianificato è 1.024 B,
senza nuova heap o aumento del massimo arena. Non è un bound di stack.
Il [record su SHA pulita](evidence.md#guard-challenge-from-the-sealed-prefix)
conserva la catena reale e i controlli del ledger.

Il ledger aggiunge 108.000 B di correzioni per ruolo, proof da 48 B,
216.085 B assorbiti nel prefisso e 32 B di digest; nessun vettore di triple.
Per il guard, incluse costruzione delle triple e maschera, conta 76.956
prodotti Fp3 / 102.606 add-sub lato prover; lato verifier 51.304 prodotti
Fp3, 25.650 prodotti Fp3×Fp e 64.130 add-sub, incluso il cambio di segno
Delta. La costruzione locale delle correzioni aggiunge 12.825 prodotti Fp
e 13.500 add-sub. Sono conteggi sorgente, esclusi istruzioni/permute hash,
trasporto, FS e lifecycle; non sono traffico HBM.

Sul seed principale da 17.553 righe il corpo heap nominato guard+seed è
669.744 B prover / 529.272 B verifier, prima di audit/allocator/stack.
Il piano conserva anche il secondo seed: non libera righe necessarie a
F_EQ. Il nuovo stato non alza il picco nominato precedente né chiude quello
fisico. Copie temporanee Auth/Key/Fp3 sullo stack non hanno ancora un audit
di cancellazione. Restano i gate del preflight e il totale ≤65 s.


## F_EQ: consumer locale dei due seed opposti

Evidenza del trasporto: [33 test Rust e 29 Python/C++](evidence.md#native-two-role-equality-transport).
Il [consumer ridotto](../../rust/volta-pcg/src/c71_seed6/equality.rs) usa
le code riservate dei due seed completati, con ruoli opposti. Corregge la
key con `k' = k - Delta*(x-r)`, mantenendo il tag originale. Entrambe le
correzioni canoniche entrano nel prefisso role-bound prima del callback coin;
ogni parte riceve il commitment peer prima di poter aprire la propria share.
Le share sommano a `(Delta0+Delta1)*(x1-x0)`. I test coprono input diversi,
framing, campi non canonici, commitment errato/riflesso e share alterata anche
prima del commitment; il caso reale usa due seed da tre righe, direzioni 0/1.

Il callback deterministico dei test algebrici **non realizza F_Rand**;
la catena cGGM ora usa la coin nativa descritta sotto. Il vincolo locale
commit-before-open non realizza trasporto atomico o burn durevole.
L'exchange F_EQ ora usa due endpoint indipendenti con i helper `send/recv`
del bootstrap: correzioni, coin e share sono nove frame ordinati. Ogni
header ha tag u8 e lunghezza u64 LE, validata prima di allocare. Il primo
commitment della share peer è ricevuto prima della propria apertura.
Il test reale composto esegue questo exchange invece di spostare i frame
direttamente fra i due stati; framing errato/troncato è respinto.
La riserva ora consuma il seed principale prima del guard: copia la sola
coda, cancella esplicitamente gli slot originali e tronca il prefisso senza
ridurne la capacità. Conserva il binding e passa a F_EQ solo code esatte;
seed non separati vengono respinti. Il raccordo seguente collega ora
guard→cGGM→split→F_EQ usando le stesse righe originali dei due seed.
Le garanzie di privacy/soundness dello screen sono condizionali a quelle
premesse: nessun credito alla composizione o alla sola coin del fixture.

Il ledger per t=675 conta, per parte, 6.751 prodotti Fp3 e 2.025 prodotti
Fp3×Fp, prima del lavoro della coin; il payload più sei header da 9 B costa
32.630 B complessivi, esclusi seed e coin, oppure **32.785 B con la coin**.
Rispetto alla prenotazione da sei byte, i nove header costano 27 B in più
sul bootstrap. Il wire ridotto è 433 B a t=1 e 481 B a t=2, misurato nei
due Audit speculari. Input, frame e coin sono
limitati in capacità; la decodifica trasferisce il frame posseduto, poi lo
rilascia. Gli Audit di setup vengono liberati prima delle correzioni.
Il massimo payload aggiuntivo è **64.800 B per parte**, oltre ai due output
Seed6 ancora vivi. F_EQ possiede ora soltanto le due code da 2.025 righe:
178.248 B per ruolo 0 / 178.200 B per ruolo 1, compreso l'envelope
aggiuntivo; il prefisso principale resta esterno e vivo nel piano.
Si aggiungono stato di valore, stack, allocator e trasporto.
`size_of` è soltanto shallow.
L'exchange riserva altri 192 B heap per i Vec Audit (capacità 4+8 record)
e fino a 96 B di read buffer temporanei; il piano mantiene i 288 B fino
alla conversione positiva. Buffer del socket/kernel e stack fisico restano
fuori da questi payload nominati. Non è un canale autenticato o una prova
di accordo atomico sull'esito, né il trasporto globale del setup.

Il piano riserva conservativamente quei 64.800 B più uno slot di stato
4.096 B mentre trattiene ancora entrambi i seed e le correzioni guard.
La separazione aggiunge una coda da 64.800 B prover / 48.600 B verifier,
più 24 B per la copia Delta del verifier. La capacità principale rimane
561.744 / 421.272 B: il picco Vec della riserva è quindi 626.544 / 469.872 B.
Copia e cancellazione contano ciascuna 64.800 / 48.600 B logici, oltre alla
lettura della copia; non sono traffico HBM misurato. L'audit e il lavoro
setup originari restano sul prefisso: lo split non ripete OT o compressione.
Il test della riserva usa seed da 12 righe, prefissi da 9 nel guard e code
da 3 in F_EQ; il test composto attuale usa 25 righe principali e 6 inverse.
Il piano conserva i seed fino alla conversione positiva nello stato EA
descritta sotto, non li libera implicitamente prima di F_EQ.
I massimi risposta restano quelli del
range; lo stack crittografico e il picco completo non sono certificati.


## Guard, cGGM, split e F_EQ a ruoli separati

Evidenza: [25 controlli Rust e 27 Python/C++ su SHA pulita](evidence.md#seed6-guard-to-cggm-and-split-equality).

Il [raccordo sperimentale](../../rust/volta-pcg/src/c71_seed6/cggm.rs) consuma
`GuardAccepted` prima di generare c. Il sender campiona c0 in Fp3 con il
sampler limitato esistente, calcola `k=c0-K(r0)` e percorre `(k,K(beta)-k)`;
il receiver possiede solo valori/tag, correzioni e cammino privato, mai
Delta o root sender. Non chiama `puncture`, che rimane un oracolo di test.
Con `d=s-r*beta`, i sibling trasmessi sono sul lato r: il puncture è quindi
`alpha=~r` sui soli h bit. La foglia alternativa è `M(beta)-sum(sibling)`.
I prefissi verificano `Macc-Kacc=beta*Delta` esattamente da alpha in poi.

I due ruoli percorrono gli alberi una seconda volta per il check di ciascun
blocco. Le tre maschere split originali danno `z=m+chi_alpha*beta`,
`w=U(M)+M(m)` e `v=U(K)+K(m)+Delta*z`. Solo le code disgiunte dei seed
entrano poi nel consumer F_EQ; root e chiavi punctured rimangono pendenti.
Le correzioni c sono tutte canoniche e fissate nel prefisso prima delle U.
Il codec rifiuta forme, cammini e nonce errati; RNG indisponibile o sampler
esaurito non restituiscono stato. Gli oggetti sono consumati, non clonati.

Il controllo esaustivo h=1–7 copre ogni cammino, tutti i prefissi, beta zero
e due blocchi; confronta anche i contatori con le formule del ledger.
La catena attuale con seed AES reali da 25+6 righe passa e rifiuta c/z alterati
attraverso F_EQ. Ora esegue entrambe le coin commit/risposta/apertura
descritte sotto; i test algebrici mantengono callback deterministici.
Il raccordo successivo aggiunge sei righe EA; restano burn durevole,
nonce freshness globale, trasporto e port canonico a trie batch.
Non è ancora un bootstrap completo né credito alla sicurezza composta.

Per t=675,h=19 i due passaggi costano 707.786.100 H sender e 707.761.800
receiver. Il ledger aggiunge maschere, campo, callback U e 129.600 B di
randomness per c0; il fallimento del sampler c0 è censito separatamente
come `3*t*((2^64-p)/2^64)^8`, senza attribuirgli una nuova prova composta.
I payload c/z sono 307.800/16.200 B; root sender 32.400 B, key+path u64
receiver 329.400 B. I temporanei per primo passaggio sono 456/912 B;
v/w usano 16.200 B per parte. Il piano conserva conservativamente seed,
correzioni guard, frame c/z e stati privati fino a F_EQ, includendo lo slot
di valori/hash da 4.096 B. I `size_of` CPU sono 712/728 B prima dello split
e 824/840 B dopo: non sono bound dello stack compilato. Il massimo globale
nominato non aumenta; FS globale, allocator, stack/spill, trasporto e
picco fisico rimangono aperti. Nessuna esecuzione H100 è autorizzata.


## Coin native per split e F_EQ

Evidenza: [27 controlli Rust e 28 Python/C++ su SHA pulita](evidence.md#native-split-and-equality-coins).

Il [protocollo locale](../../rust/volta-pcg/src/c71_seed6/coins.rs) sostituisce
i coefficienti prefissati della catena reale con commit/risposta/apertura.
Il commitment BLAKE3 usa il dominio `VOLTA-C71-DORY-COIN-v1`, nonce 32 B,
prefisso 32 B, fase u8 (split=0, equality=1), direzione u8 (=1), numero di
coefficienti u64 LE e apertura `s1||blind` da 64 B. Dopo il commitment il
sender fissa c e s0; il receiver decodifica tutto c prima di aprire. Per
F_EQ entrambe le correzioni chosen-input sono congelate prima della coin.
Il seed XOR alimenta SHAKE256 nello stesso dominio con `/coefficients/`,
nonce, prefisso iniziale, fase, prefisso successivo, cardinalità e seed.
Questi 173 B hanno lunghezza e ordine canonici.

Un solo XOF per coin/ruolo produce slot da 192 B per Fp3, con otto tentativi
per limb e fallimento terminale. Le foglie receiver sono visitate in ordine:
sibling sinistri dal livello esterno all'interno, alpha, poi destri
dall'interno all'esterno. Due scan dei bit bastano; nessun sort o vettore U
di dimensione N. Il callback fallibile respinge prefisso/indice errato,
riuso e consumo incompleto, senza poter riprendere lo stream dopo errore.
F_EQ propaga anche gli errori della coin e dell'entropia della share.

I vettori Python/Rust verificano lo stream; i test coprono fase, apertura
alterata/troncata, RNG indisponibile e ordering. La catena reale conserva
positivo e rifiuto c/z; nel caso c alterato entrambi i ruoli usano lo
stesso prefisso alterato, quindi il rifiuto non si limita a una divergenza
di transcript. La randomness è riproducibile nei test, non una stub delle U.

Il payload di ogni coin resta 128 B. Ora split e F_EQ usano entrambi tre
header nativi da 9 B (**155 B per coin**).
Sono già inclusi nel bootstrap aggiornato, senza sommarli due volte. Per ruolo la coin
split assorbe 173 B e produce **67.947.724.800 B di XOF**, quella F_EQ
129.600 B. Sono byte generati localmente, non wire o traffico HBM. Si
contano anche commitment, RNG e candidati del sampler. Lo stato stream
CPU è 488 B, i due stati di fase 144 B ciascuno; un solo slot conservativo
da 4.096 B copre i valori/hash, non lo stack compilato. Il massimo arena
nominato resta invariato. La coin nativa non scarica da sola l'ipotesi ROM:
Transcript del run, burn durevole senza retry, canale autenticato e
collegamento alla capacità PCG canonica restano aperti, senza nuovo credito H100.


## EA puntuale dopo accettazione F_EQ

Evidenza corrente: [32 test Rust e 29 Python/C++](evidence.md#global-ea-accumulator-correction).
La [versione `228ed64`](evidence.md#equality-owned-pointwise-expansion)
rimane NO-GO multiblocco: il controllo t=1 non rilevava l'omissione dei
blocchi precedenti. Il difetto è riprodotto sulla seconda riga del fixture
t=2 e ora corretto con prefissi globali e confronto diretto con BAe.

Il [consumer sperimentale](../../rust/volta-pcg/src/c71_seed6/expand.rs) riusa
EAGen e Acc/PuncAcc esistenti. F_EQ ora possiede lo stato cGGM pendente:
solo `Accepted<State>` permette la conversione, mentre un rifiuto distrugge
lo stato trattenuto. Dopo il successo il sender conserva k/Delta e i
prefissi K(beta); il receiver conserva alpha, prefissi beta/M(beta),
sibling e foglia alternativa, mai root
sender o Delta. Il receiver legge la chiave punctured senza copiarla,
con scratch fisso da 20 elementi Fp3. Non materializza un pool denso.

Un cursore monotono produce al più `floor(t*2^h/5)` righe base, ciascuna
con gli stessi termini pubblici EA nei due ruoli. Per il receiver,
`x=sum_j(chi_j*sum_i(beta_i*[j>=i*2^h+alpha_i]))`; l'identità dei prefissi
dà `m=k+Delta*x`. Per ogni termine EA il prefisso locale si somma a tutti
i blocchi precedenti, usando somme cumulative anziché uno scan per termine.
Il controllo reale h=4,t=2,ell=2 usa seed principali/inversi da 25+6 righe,
produce sei righe, le confronta con BAe e verifica due packing Fp3 nonzero.
c/z alterati non producono la capacità. Un test controlla il drop degli
stati trattenuti su rifiuto; un altro forma, capacità e fallimento reale
del sampler EAGen. Errore o richiesta oltre capacità avvelenano il cursore
e cancellano i buffer segreti posseduti; non sostituiscono un journal.

Per la geometria selezionata il payload heap dopo conversione è
32.400 B sender / 351.000 B receiver. M(beta) è incorporato nella
foglia alternativa e riaccumulato nei prefissi; alpha usa u64. La conversione
aggiunge 21.600 B per i prefissi beta/M(beta) receiver mentre lo stato
precedente è ancora vivo; poi rilascia seed,
correzioni e frame consumati. Il piano conserva inoltre il precedente
slot persistente conservativo, senza reclamarne un risparmio o un nuovo
picco. Una riga usa al più 409 B heap EA/hash e 480 B di scratch receiver,
oltre allo slot di valori/hash da 4.096 B, non bound dello stack compilato.

Il riferimento puntuale costa **198 H sender per riga base**, al più
198 receiver, più 22 SHAKE EAGen, 11 prodotti Fp3×Fp per ruolo e
11 coppie prodotto/somma Fp receiver. Questi non sono i costi del trie
batch selezionato e non entrano come sostituto nel budget canonico.
I prefissi aggiungono 11 somme Fp3 per riga/ruolo e 11 sottrazioni sender;
la conversione costa 1.350 somme Fp3 sender, 13.500 receiver e 1.350 somme
Fp receiver. Il piano persistente canonico conserva lo slot M(beta), ora
cumulativo, con alpha u32; non confonde questo layout con quello nativo u64.
I contatori runtime registrano righe complete: su errore del sampler
sono parziali, con upper pari al lavoro di una riga tentata intera.
Il seed EA nel fixture ora deriva dalle aperture F_EQ come sotto, non è
prefissato dal caller. Restano composizione ROM/binding globale, trasporto, burn durevole,
trie batch, bridge alla proof, erasure di stack/spill e picco fisico.
Nessun credito alla composizione malevola, al refinement Lean o a H100.


## Seed EA dalle aperture F_EQ

Evidenza: [34 test Rust e 30 Python/C++](evidence.md#ea-seed-from-accepted-committed-openings).
Solo dopo verifica dei commitment e della somma delle share, `Accepted`
contiene il nuovo binding/seed pubblico di 32 B. È SHAKE256 di
`VOLTA-C71-Seed6-equality-v1 || /accepted-EA/ || frozen_prefix32 || opening0_56 || opening1_56`.
Ogni opening è `share24 || blind32`; l'ordine è quello dei ruoli, non di
ricezione. Sono **184 B assorbiti e 32 B prodotti per ruolo**, senza nuovo
wire, RNG o heap. Il costruttore EA consuma il seed di `Accepted` e non
accetta più un parametro seed esterno. Seed zero, apertura non canonica,
commitment errato o mismatch non rilasciano lo stato. Lo slot di valori/hash
già riservato resta conservativo, non un bound dello stack compilato.

La scelta riusa i blind freschi di F_EQ, non la coin delle U già pubblica
prima del confronto: entrambe le share sono committate prima che il blind
onesto sia aperto. Nel ROM, fuori da collisioni/prequery del blind onesto,
il nuovo dominio dà una coin pubblica fresca con abort, senza rivelare
nulla oltre alle aperture già previste. Come envelope locale prudente a
Q=2^74 il ledger registra `Q*(Q-1)/2^257 + (2*Q+1)/2^256 < 2^-108` per
collisione, prequery e zero, oltre agli errori primitive già censiti.
È condizionale a randomness fresca, binding/hiding dei commitment e burn
senza retry; il trasferimento congiunto sotto EA-LPN-SL e l'indipendenza
richiesta dalla riduzione non vengono dichiarati provati dal test.
Non è fairness, UC, una nuova ipotesi o un lemma Lean aggiuntivo.

Il KAT Python/Rust verifica codec e ordine; modifiche a prefisso, ruolo o
blind cambiano il seed. La catena reale a due blocchi usa lo stesso seed
derivato nei due endpoint e conserva confronto BAe, MAC e rifiuto c/z.
I vettori EAGen con seed prefissato restano soltanto test del sampler.


## Setup Seed6 su un solo canale

Evidenza: [37 test Rust e 31 Python/C++](evidence.md#one-channel-seed6-setup).
Il [driver sperimentale](../../rust/volta-pcg/src/c71_seed6/setup.rs) esegue
su un unico canale: seed principale, seed inverso, riserva disgiunta,
guard, prima coin/cGGM, split, F_EQ trasportata e conversione EA. Nessun
ruolo riceve i segreti peer. t/h/ell/capacità entrano nel digest del
contesto bootstrap prima degli OT; una diversa ell viene respinta nella
handshake, anche se forma e numero di righe coincidono. Il nonce cGGM è
BLAKE3 dei due binding sigillati, in dominio setup distinto. Il receiver
riusa beta dai valori originali e campiona h bit uniformi per ogni cammino
con 8 B RNG per blocco, cancellando i buffer privati intermedi.

Il controllo h=4,t=2,ell=2 attraversa realmente il doppio MR19/AES da 25+6
righe, produce sei MAC base e ferma l'esaurimento. I due Audit sono
speculari: **390.742 B totali**. Le coin sono deterministiche solo per
riproducibilità del test; beta e cammini non sono più forniti a mano.
La geometria invalida è respinta prima di I/O/RNG. Rimangono separati i
test BAe multiblocco e i rifiuti c/z della catena componente precedente.

Il wire canonico delle primitive è ora **61.841.366 B**, calcolato dagli
stessi seed e frame: 16 messaggi dopo i seed, con header da 9 B. I **45 B
aggiunti** sono quattro header guard/d/c/z prima esclusi dal payload
(36 B) e i 9 B aggiuntivi della coin split rispetto alla prenotazione.
I 27 B F_EQ erano già inclusi. Non si aggiungono nuovi payload crittografici.
Geometry/nonce richiedono due BLAKE3 per ruolo, con 98/102 B assorbiti.

Il ledger include 108.000 B temporanei per il frame delle correzioni,
5.400 B ciascuno per cammini e beta receiver, 896 B heap degli Audit
restituiti e 672 B di valore nativo. Uno slot aggiuntivo da 4.096 B riserva
valori/hash, non certifica lo stack. Il piano conserva prudentemente i
cammini/beta anche durante la conversione e i diagnostici fino al consumer;
non accredita la liberazione di alias privati. Il massimo globale nominato
resta quello della risposta, non un picco fisico completo.

Questo chiude il percorso byte del setup ridotto, non autenticazione del
canale, lifecycle completo, transcript del run, port accelerato,
bridge al pool/proof canonico o composizione crittografica. Il modulo è
disponibile soltanto nei test o nella feature CPU opt-in descritta sotto;
nessuna esecuzione canonica, GPU o spesa è autorizzata.

### Journal monouso del setup

Evidenza: [46 test Rust e 31 Python/C++](evidence.md#one-use-seed6-setup-journal).

L'entry `sender_once/receiver_once` riusa il journal `Lifetime`, non un
secondo formato o lock. Il record sperimentale 5 prenota l'intera capacità
EA prima di RNG/header/OT, con write+fsync: dopo errore, drop o successo
non sono disponibili retry, rinnovo B12 o reopen. È ammesso solo nei test
o nella feature `c71-seed6-reference`,
per capacità multiple di tre fino a 70.778.880 righe. L'output possiede
un borrow esclusivo del journal insieme allo stato EA; non può sopravvivere
al suo owner né estrarre pubblicamente uno stato riutilizzabile.

Il binding aggiunge un BLAKE3 per ruolo, dominio
`VOLTA-C71-Seed6/lifetime/`, con 201 B assorbiti e 104 B heap temporanei
del modello. Installazione e setup scrivono 104+57=161 B per ruolo;
installazione sincronizza file e directory, il record sincronizza il file,
con un lock OS mantenuto fino al drop. Nessun byte wire aggiuntivo.
Lo slot valori/hash già nominato resta 4.096 B, non un bound di stack;
metadata OS, allocator e latenza fsync restano da misurare. Il massimo
arena nominato non cambia, senza credito di picco fisico completo.

I controlli ridotti coprono RNG fallito dopo burn, capacità invalidata
prima del record, rifiuto retry/reopen e setup reale fino a sei MAC con
owner vivo. Le regressioni del journal B12 conservano dominio e record 4.
Il filesystem non dimostra non-rollbackabilità: una copia/reset esterna
viola la premessa dell'owner. Il raccordo per tentativo seguente non chiude
NoPeek, accettazione del verifier completo o pool/proof; nessun nuovo
credito compositivo o Lean.

### Riserve streaming per tentativo

Evidenza: [48 test Rust e 31 Python/C++](evidence.md#bounded-seed6-attempt-windows).

Le finestre EA riusano `Lifetime::attempt`, estratto dal pool denso B12
senza cambiarne record, dominio o API pubblica. Il record 2 brucia l'intero
intervallo di `3*full_fp3` righe e il relativo slot prima di generare la
prima riga. Il callback riceve un iteratore limitato, non lo stato EA
o un Vec della riserva; ogni riga posseduta usa `Zeroizing`. L'iteratore
termina al confine della finestra. Consumo incompleto, errore del generatore
anche ignorato dal callback, panic, conteggio invalido o digest invalido
fermano il run senza promozione. L'assenza di digest conserva la semantica
B12: il risultato locale può tornare, ma lo stato non è riutilizzabile.

Solo il record 3 sincronizzato promuove l'head; il terzo tentativo
accettato termina la capacità residua. I test usano tre intervalli ideali
disgiunti e, separatamente, due intervalli reali da tre righe della catena
Seed6. I digest accettati sono **fixture**, non ricevute di una prova PCS/GKR:
il consumer resta tenuto a Prepare NoPeek e verifica completa prima di
restituirli. Il raccordo al wrapper composto è ancora aperto.

La finestra non materializza la riserva intera: mantiene contatore/flag,
una riga da 24/32 B e ora un batch limitato a 4.096 righe, descritto sotto.
Ogni tentativo accettato aggiunge 114 B disco e due fsync per ruolo;
installazione, setup e tre accettazioni totalizzano 503 B e nove sync.
Owner e Audit restano vivi durante le risposte: lo slot valori da 4.096 B
e 896 B heap diventano persistenti nel piano (+5.120 B allineati), non
sono liberati solo perché termina il setup. A O=300 la coda nominata
diventa 276.291.840 B, 7.856.384 B oltre 256 MiB. È accounting di liveness,
non picco fisico completo o costo fsync misurato. Il riferimento puntuale
resta separato dal percorso batch ora implementato.

### Trie batch nei due ruoli

Evidenza: [51 test Rust e 32 Python/C++](evidence.md#seed6-bounded-union-trie-batches).

Il [raccordo EA](../../rust/volta-pcg/src/c71_seed6/expand.rs) genera fino
a 4.096 righe della riserva corrente, ordina i termini pubblici per indice
e visita una volta ogni nodo necessario con un [walker depth-first](../../rust/volta-pcg/src/c71_seed6/trie.rs).
Non alloca un albero completo o un pool denso. Il sender usa `(k,offset-k)`
alla radice; il receiver ricostruisce bottom-up il cammino modificato e
applica H solo ai sottoalberi sibling. Ogni foglia emette l'accumulatore
inclusivo più il prefisso degli alberi precedenti, per tutti i termini
duplicati che la usano. Non cambia EAGen, il binding o il seed pubblico.

I confronti esaustivi h=1..6 coprono ogni puncture/prefisso e query duplicate;
il caso reale t=2,h=4,ell=2 conserva BAe globale e MAC/Fp3 originali.
Per sei righe, il sender usa **41 SHAKE (17 H + 24 EAGen)**, il receiver
36; il riferimento sender puntuale ne usava 60. Il test da 4.096 righe
copre solo termini pubblici canonici, non un bootstrap canonico. Il test
di lifetime attraversa 4.096+5 righe e poi una distinta riserva da tre,
senza prefetch oltre il burn. Ogni batch precedente è distrutto prima
di generare il successivo; errori o lunghezza errata non rilasciano righe.

Il payload CPU nominato è **1.081.344 B** per 45.056 termini da 24 B,
98.304/131.072 B di output sender/receiver e scratch del codec. I picchi
heap nominati sono 1.179.746/1.212.514 B, senza allocator. La visita ha
al massimo 20 frame; uno slot prudente da 64 KiB per valori ricorsivi
non è una misura dello stack compilato. Questi payload rientrano nel più
ampio envelope pubblico/frontier già prenotato: non si riduce il piano,
né si accredita un alias fisico implementato o un port CUDA.

L'upper H di un batch pieno è 625.722 per ruolo, escludendo la radice
indipendente; il ledger mantiene l'upper prudente precedente 626.397.
Il ledger corregge anche PuncAcc a `(2h+1)*termini` somme Fp3 e aggiunge
le sottrazioni dei prefissi globali sender per albero visitato. I counter
nativi comprendono confronti di sort/partizione e operazioni di campo;
non ne deriva un costo canonico completo o service-rate H100. Sono ancora
aperti sorting canonico, stack/erasure compilati, NoPeek e accettazione
del wrapper PCS/GKR, composizione e picco fisico.


### Interfaccia CPU opt-in e algebra MAC condivisa

Evidenza: [58 test Rust e 32 Python/C++](evidence.md#seed6-opt-in-external-role-pools).

La feature `volta-pcg/c71-seed6-reference`, disabilitata per default,
espone soltanto `prover`, `verifier`, geometria validata e pool opachi
con contesto pubblico, diagnostici, stop e riserva limitata. I costruttori
usano OS RNG; non accettano seed/Delta o stato EA del caller. Gli entry
di produzione non la chiamano e non esiste fallback automatico dalla GPU.
L'owner continua a fornire canale autenticato e store non-rollbackabile;
il callback deve completare Prepare NoPeek e verifica prima di restituire
la ricevuta. Il segno base è ancora `m=k+Delta*x`; MAC/PCS usano `-Delta`.

L'algebra Fp3 pura (tipi, transfer e prodotto) viene spostata senza cambiare
le formule in `volta-pcg::c7_fp3`, e ri-esportata dai percorsi MAC originali.
La ragione è concreta: PCG non può dipendere da MAC, che già dipende da
PCG. Non si duplicano formule né si aggiunge un trait di callback.
I lift B4/B5 respinti e i relativi test restano nel modulo MAC e mantengono
i loro limiti scientifici. Le API MAC precedenti continuano a funzionare.

Un test d'integrazione compilato come crate esterno usa la nuova API con
OS RNG, esegue setup reale 25+6, riserva tre righe e verifica packing e
transfer originali Fp3, poi stop/reopen reject. La ricevuta è un fixture,
non una proof di inferenza. Sono invariati wire, heap dei pool e layout
dei MAC; non si accredita un nuovo picco o runtime. Il solo test esterno
non sostituisce il raccordo al wrapper PCS/GKR descritto di seguito.

Il [record ridotto](evidence.md#native-exact-size-correlation-streams)
controlla che il corpo composto e i relativi consumer ora accettino
`ExactSizeIterator<Item=Auth/Key>`, non richiedono `Vec::IntoIter`.
È il trait standard minimo che conserva tutti i controlli di cardinalità
prima delle fasi e l'esaurimento finale. Il positivo streaming O=0 usa
un `Take` preso in prestito anziché copiare la riserva in un nuovo Vec;
la sorgente del fixture resta ideale. Non cambiano algebra, FS, numero
di MAC o conti canonici; nessuna riduzione del picco fisico è attribuita
a questo cambio d'interfaccia.

### Wrapper PCS/GKR Seed6

Evidenza: [otto test Rust e 35 Python/C++](evidence.md#seed6-complete-reduced-native-proof).

Il wrapper interno ora possiede due varianti esplicite del pool, senza
duplicare la macchina di accettazione. `volta-pcs/c71-seed6-reference`
abilita quella Seed6, mai come fallback. Il packing usa tre righe originali
e i medesimi helper del denso; `Range.map` conserva `ExactSizeIterator`
senza Vec della riserva. Prepare termina prima del burn e dell'esposizione
dei MAC inutilizzati. Errori di generazione, triple incomplete o codec
non canonici causano panic nel consumer infallibile, intercettato dal
journal che conserva il burn e termina il run. Solo Verify completo può
produrre la ricevuta; i journal precedono le rispettive promozioni.

Il ledger ora comprende per MAC Fp3 tre moltiplicazioni e due somme per
ruolo, inclusa l'aritmetica della base costante; cinque/quattro decode
canonici per prover/verifier e una negazione di Delta per tentativo.
Il payload delle tre righe vive è 96/72 B e non aggiunge heap. I valori
rientrano nello slot prudente preesistente, non in un bound dello stack
compilato: nessuna riduzione del piano o nuovo credito di picco fisico.
Sono conti di sorgente, non istruzioni, HBM o tempo. Il primo controllo
positivo O=0 usa t=4/h=19/ell=11, main 107 + inverso 12 e 264.147 righe
base: 88.049 MAC Fp3 entrano nell'intera schedule originale; i due journal
e i registri terminano con la stessa ricevuta. Il certificato misura
circa 7,76 MB; il run positivo su SHA pulita termina in 50,11 s entro 60 s/2 GiB.
Quel tempo riguarda entrambi i ruoli CPU, non un obiettivo H100.
Il grafo rimane un layer/hidden2/prompt1+generato1 con Snapshot/A densi;
non trasferisce sicurezza parametrica o credito del run completo a tre
tentativi, reader ordinato, modello canonico, Γ reale o picco fisico.
Ogni ruolo promuove dopo il proprio journal: non si rivendicano commit
atomico distribuito o fairness fra i due ruoli.
Il controllo separato altera l'ultimo byte del completamento: entrambi
i ruoli terminano dopo aver bruciato 264.147 righe, con head del journal
zero e nessuna promozione A/KV. Passano anche shortage prima di Prepare/
decoding e consumo parziale senza ricevuta accettata. Il run positivo e
quello negativo hanno installazioni indipendenti, non un retry del pool.

Il wrapper può ora possedere sorgenti `Auxiliary` diverse usando la stessa
macchina pending/accepted. Il reader ordinato O=0 non è più un tipo
definito soltanto nel test: il suo Prepare condivide W/profilo immutabili
tramite Arc, valida il replay prima della root e riusa `fresh_pcs_coins`
con OS RNG, senza accesso ai MAC. Snapshot resta la rappresentazione del
positivo Seed6 registrato sopra. La continuazione ora prende i reader dal
proprio array accepted, senza importare root, KV o ricevute dal certificato.
Condividere gli owner evita copie delle sorgenti, ma aggiunge metadati e
refcount CPU; non è una misura del picco fisico né un risparmio canonico.
Il positivo ordinato ideale ora attraversa Prepare, pending e promozione
comuni, senza percorso speciale o coin PCS prefissati del test; il
tentativo successivo con prompt invalido termina senza modificare il predecessore accettato.
Il confronto del nuovo Prepare controlla ogni byte contro Snapshot originale.

Passa anche la [proof congiunta con reader ordinato e Seed6 reale](evidence.md#ordered-source-with-real-seed6) a
t=4/h=19/**ell=2**: 264.147 righe base, 88.049 MAC Fp3 e ricevuta reale
comune ai due journal, senza Snapshot/A densi. Il run su SHA pulita termina
in 47,43 s entro 60 s/2 GiB. I test reali densi e il profilo canonico
mantengono ell=11: questo ridimensionamento serve soltanto al controllo
CPU locale e non trasferisce il bound crittografico del profilo selezionato.
La [continuazione numerica O=2/4](evidence.md#ordered-numerical-history) condivide soltanto i KV Frozen dei reader
precedenti; i loro owner accettati conservano ancora i propri cut/cache PCS.
I controlli confrontano ogni byte D12 e tutti i KV, incluso il token finale,
e respingono cardinalità, ordine e installazione W differenti. Il getter
grezzo mantiene il dominio Boolean minimo; il reader PCS aggiunge il
padding pubblico a D12. Non sono tre proof ordinate accettate, un run AES
a tre tentativi, Γ reale o picco completo.
Il controllo end-to-end di due proof ordinate con MAC ideali è stato
arrestato a 60 s dopo la prima accettazione. Il
[record del timeout](evidence.md#ordered-numerical-history) conserva il
prefisso; il test è ignorato localmente, senza estendere il limite e
senza promuovere quel prefisso a una continuazione O=2 verificata.

Il [verifier canonico](evidence.md#canonical-verifier-with-seed6-capacity) ora riusa `VerifierCapacity`, incluso il packing lazy
Seed6, invece di imporre un pool denso e una seconda conversione di chiavi.
Il suo corpo richiede ancora la riserva compilata esatta e l'esaurimento
finale; il test del prefisso usa un Map senza Vec di chiavi. Il controllo
reale del wrapper aggiunge lo shortage Seed6 25+6, senza estrarre una sola
riga, decodificare una proof o promuovere stato. Questa integrazione non
fornisce un certificato canonico positivo né un nuovo picco misurato.

Il [provider originale compatto P0](evidence.md#original-p0-compact-provider) è condiviso col runner ridotto e non
contiene più loop hidden=2. Deriva inner, forma delle sorgenti, padding,
reshape testa/token e row-offset dal medesimo layout del verifier. Il
confronto con il vecchio oracolo alimenta una proof P0 piccola con PCS W/A
originali; inner=3 è controllato separatamente. Questo non esegue Gemma
né implementa la schedule P0 fisica a quattro letture: il riferimento
ridotto conserva il Vec dei compact, e il ledger canonico resta invariato.

## Seed6: seal di completamento

Evidenza: [29 controlli Rust e 28 Python/C++ su SHA pulita](evidence.md#seed6-completion-seals).

Il [meccanismo di seal B12](../../rust/volta-pcg/src/c71_bootstrap.rs) è ora
riusato dall'adapter Seed6. Il verifier genera 32 B freschi soltanto dopo
check K6, compressione e rifiuto della chiave zero; il frame fisso ha dominio
`C71S6S01` e 40 B totali. Entrambi i ruoli restituiscono l'output soltanto
dopo il seal. Il nuovo binding è BLAKE3 di `VOLTA-C71-Seed6-completed-v1`,
binding della handshake e seal, e alimenta guard, code F_EQ e coin.
Troncamento, dominio errato, seal zero o entropia indisponibile fermano
il percorso. Il dominio B12 originale `C71B12S1` resta invariato.

La handshake diventa `C71S6v02`, suite 5: un peer v01 senza questo obbligo
viene respinto prima degli OT, non silenziosamente accettato con un tail
di trasporto diverso. Non cambiano lunghezze o budget analitico: i 40 B
per seed erano già contati. Il ledger aggiunge la fase seal dopo il
rilascio dei K6, 32 B RNG verifier, hash del binding e oggetti nominati;
non aumenta il massimo arena globale. Le evidenze v01 rimangono immutabili
e non attestano il nuovo ordine del completamento.

Il seal fissa un identificatore fresco, **non un burn durevole**. L'entry
monouso ora prenota entrambi i setup nel journal prima di RNG e impedisce
retry anche su errore o withholding; le finestre per tentativo ora riusano
il journal, ma transcript globale e proof restano da collegare. I test locali non conferiscono nuovo credito alla
riduzione composta, al picco fisico o all'H100.


## EXP30: massimo con un solo checkpoint

Il vecchio albero massimo conserva coppie Fp3 a tutti i livelli: per N=2^27
e key_bits=8 occupa 12.859.736.064 B; per N=2^28 e key_bits=9 occupa
25.744.637.952 B. Le assegnazioni dense aggiungono
2.147.483.648 / 4.294.967.296 B. Quel backend è NO-GO per arena.

Il caller usa ora assegnamenti lookup e lo stesso `prove_tree_sourcewise`
dell'endpoint byte. Il getter restituisce i quattro figli originali;
i numeratori sono zero pubblico, i prodotti interni sono in Fp e le foglie
sono i32, incluso il valore -1 ammesso dall'encoding. Tiene un solo livello:
rilascia il vecchio prima di allocare il successivo e rilascia l'ultimo
prima del lookup EXP30 e del GKR ratio. Nessuna sorgente dipende dalle sfide;
i byte D provengono dalla stessa A immutabile già legata al transcript.

| O | Checkpoint massimo | Getter byte D | Prodotti Fp per costruzione | Scritture checkpoint | Letture logiche checkpoint |
|---:|---:|---:|---:|---:|---:|
| 0 | 536.870.912 B | 347.904.000 | 152.208.000 | 1.602.224.128 B | 41.188.065.280 B |
| 150 | 1.073.741.824 B | 1.168.992.000 | 519.552.000 | 3.212.836.864 B | 85.748.350.976 B |
| 300 | 1.073.741.824 B | 1.946.592.000 | 865.152.000 | 3.212.836.864 B | 85.748.350.976 B |

La ricostruzione legge ogni cella valida a ogni livello, senza salti per
valore zero. `source_tree_trace` conta separatamente Eq, fold e coefficienti
cubici; il ledger producer aggiunge il massimo a RMS/ratio e divide per
il budget 0,8 s solo per ricavare soglie di throughput, non un tempo.
Il piano degli indirizzi conserva cut del getter e pesi insieme al checkpoint.
I cut restano vivi attraverso lookup e ratio, inclusa la LUT byte, fino
all'ultimo consumer originale. Workspace/liveness di lookup, GKR,
proof/correlazioni e allocator restano da unire; il lookup usa ora la cache
compatta e il cut descritti sotto, senza ammissione del piano completo.
Le letture/scritture sono accessi sorgente, non transazioni HBM misurate.

Il confronto ridotto esaurisce ogni figlio contro il vecchio albero e
confronta wire, punto, Auth, triple, batch prodotti, consumo delle righe e
FS. La prova softmax e la composizione ridotta restano controlli di regressione.
Il massimo componente non è il picco fisico completo o un credito di tempo.
Dopo il join del lookup sotto, i massimi nominati di questa catena sono
2.082.995.968 / 3.370.001.152 / 3.851.690.752 B; il massimo integrato
nominato aggiornato con owner/Audit persistenti è 6.166.159.104 B.
Il tipo `Fn` non impone da solo immutabilità/NoPeek: il caller deve continuare
a legare il reader ai byte originali fissati, senza accesso ai MAC non spesi.

## Lookup: cache originale e albero tagliato

Il lookup riguarda GELU, softcap e EXP30. EXP30 interroga **tutto** il dominio
D/E originale, compresi i padding causali: 60×8192×(O+150) query, quindi
73.728.000 / 147.456.000 / 221.184.000. Non si possono usare le sole celle
vive del GKR ratio per ridurne il conto o il predicato. GELU ha 193.536.000
query e softcap 13.107.200; i rispettivi istogrammi hanno 3.932.100 e 65.535
righe, con 3.932.100 righe anche per EXP30.

L'albero denso occupa `48*(2P-1)` B per dominio padded P: 25.769.803.728 B
per GELU, 12.884.901.840 B per EXP30 O=0 e 25.769.803.728 B per O=150/300.
Questi backend sono NO-GO per arena già prima di domain, Eq e sorgenti.
Il solo albero softcap occupa 1.610.612.688 B e non viene escluso dal medesimo
lower. Restano separati fallimento del backend e fattibilità della relazione.

Il port locale conserva query/istogrammi originali compatti,
un albero superiore tagliato a gruppi di 16 foglie e rigenera gli ultimi
quattro livelli, usando lo stesso sumcheck. Cache più albero superiore:
2.400.485.088 B GELU, 153.354.188 B softcap e
1.263.402.720 / 2.511.077.088 / 2.953.445.088 B EXP30.
Sono payload nominati, esclusi descrittori delle sorgenti, proof, correlazioni,
source provider e allocator. Il ledger conta costruzione, rigenerazione,
visite anche padded, tag e endpoint Eq; letture logiche e operazioni sorgente
non diventano traffico HBM o istruzioni GPU. Le cache chiamano ogni getter
originale una sola volta, nell'ordine originale; il tipo stretto è selezionato
solo dal wrapper i16, mai inferito dalle tabelle pubbliche per query i32.
Il verifier genera i tag pubblici dal descrittore e scorre Eq senza dominio
denso. L'albero superiore viene rilasciato prima dell'endpoint MAC, le cache
dopo; i cut A rimangono vivi fino all'ultimo consumer originale del caller.
Il piano include anche descrittori, righe, triple, metadata dei livelli,
stack dei sottoalberi, punto ed Eq. I tre buffer proof rimangono prenotati
fra tutte le catene fino al consumer della risposta: 137.984 / 141.312 /
141.312 B allineati, senza dedurre un rilascio dal ritorno della funzione.
Sono richieste ABI pianificate, da collegare all'allocator nativo. Il binding
aggiunge il payload noto delle tabelle; la copia del profilo effettivo resta
un requisito esplicito nell'evento. Nessuna allocazione ignota vale zero.

GELU arriva a 3.220.099.584 / 3.259.424.512 / 3.298.746.112 B nominati.
Non è ancora un picco completo. La parità ridotta confronta prova densa,
punto, MAC, consumo righe e prossimo FS, con query i32 oltre i16 e punti
Eq Boolean/non-base. Immutabilità del getter resta una premessa del caller.

## Capacità native GKR e endpoint byte

Il census locale misura capacità di programmi, backing delle righe anche
dopo il consumo dell'iteratore, prove annidate, triple, punti, edge e vettori
intermedi. Distingue binding, round sulle celle, riduzione degli indici e
LUT byte; input/current/next sono rilasciati prima di quest'ultima. Conta
insieme vecchi e nuovi pesi nella transizione, compresi i vettori Eq interni;
nessuno shrink di capacità segue dal solo consumo logico.
Il binding mantiene lo stesso frame FS e dichiara il chunk da 4 KiB.
I piccoli test confrontano le capacità osservate con i payload logici;
il census della forma canonica riporta soltanto quantità richieste/logiche,
non capacità osservate su un'esecuzione canonica. Il census include anche Eq root/leaf, compresi vecchio e nuovo buffer vivi
insieme. Prefissi RMS/byte/lookup e AttemptContext hanno prenotazione esatta;
le strutture del sumcheck sorgente prenotano livelli, round, punti e triple.
`record_values` usa lo stesso frame FS in streaming, con un codec stack di
24 B; i test lo confrontano con il frame contiguo, incluso il caso vuoto.
La dimensione osservata di CompactBlock è 32 B sull'ABI della build locale;
un'ipotesi iniziale di 40 B è stata respinta dal test, prima del join.
Caller, allocator, transcript interno, altre riallocazioni e workspace
esterni restano esplicitamente esclusi.
Questa strumentazione non rende completo il picco né il lavoro temporale.


## Percorso critico integrato ridotto

Il test `c71_b12_native_streaming_lookup_gkr_whir_positive_original_macs`
usa il runner/verifier originali con reader ordinato e PCS replay. Il
positivo O=0 produce circa 7,75 MB e consuma 88.049 MAC ideali; Snapshot e A
completa non sono materializzati nel percorso selezionato. Un controllo
separato confronta i byte del reader con l'oracolo Snapshot; range e
linear hanno inoltre parità wire/FS/endpoint con il denso. Questo chiude
il raccordo di correttezza, non i costi del port canonico.

Il ledger `reduced_joint_trace` in
[c71_response_trace.py](../../scripts/c71_response_trace.py) partiziona le
chiamate numeriche ai confini reali del runner. Il
[record su SHA pulita](evidence.md#integrated-positive-and-scalar-main-cell-no-go)
conserva log, ledger e compilazione. Per la sua singola proof:

| Fase del getter | Righe producer eseguite | Letture scalari W | Letture scalari A |
|---|---:|---:|---:|
| Preparazione prima del commitment | 219 | 222 | 606 |
| Commitment A iniziale | 70.016 | 78.848 | 197.376 |
| Relazioni producer | 21.016.027 | 22.764.640 | 57.498.846 |
| Range A | 329.879 | 371.260 | 929.880 |
| Linear A e WHIR | 32.793.738 | 36.943.680 | 92.460.372 |

Sono contatori CPU del riferimento, non accessi HBM e non una stima H100.
Il commitment iniziale usa casualità fresca: proof e query WHIR, e quindi
i conteggi dipendenti dalle query, possono variare fra run.
Le callback di GKR/lookup/PCS sono già pagate qui; i relativi contatori
aritmetici coprono soltanto il consumer. I picchi componenti non vengono
sommati né presentati come picco fisico completo. I 512 replay canonici
non vengono sostituiti con le rigenerazioni di questo riferimento ridotto.
I tempi H100 `T_inference`, `T_proof_only`, `T_response_total` restano da
chiudere; ogni ricostruzione qui ripetuta appartiene a `T_proof_only`.

Il kernel CUDA `previous_fold_current_coeff_kernel` fonde il fold MSB
precedente, con sfida già disponibile, e i coefficienti del round corrente.
La sfida corrente viene solo dopo autenticazione/record/riduzione. I cinque
vettori materializzati consumano 480 B letti + 240 B scritti per coppia;
il percorso separato ne consuma 960 B. Il lavoro resta 28 moltiplicazioni,
23 addizioni e 15 sottrazioni Fp3 per coppia, più riduzione. Nessun credito
di tempo per la sola banda risparmiata. Il primo round è coefficient-only;
il fold terminale rimane separato. La modalità `--fused-gkr LOG2_N REPS`
verifica tutti gli output e la riduzione globale prima di cronometrare il
componente; richiede input/output disgiunti e non include producer/getter,
FS, autenticazione o PCG. Il test host distingue l'ordine MSB da quello
adiacente del vecchio microbenchmark. Non è ancora il kernel main-cell
And/Xor/Copy né una sua misura sostitutiva.


## NO-GO del main-cell scalare fuso

`c71_gkr_main_cell_fused` implementa il nucleo di `source_cell_round`:
una voce pubblica programma/cella supportata per thread, input lo/hi già
foldati, loop dei gate And/Xor/Copy, accumulo del polinomio quadratico e
applicazione del selettore una sola volta per programma. L'oracolo CPU
confronta la valutazione del cubico con la relazione originale su 0, 1
e punti Fp3 non-base. `sm_90`, nvcc 12.9.86, produce 130 registri,
24.576 B shared, zero stack e zero spill. È un kernel di coefficienti;
getter, fold iniziali, indici, FS/MAC e riduzione globale aggiuntiva sono
esclusi dal lower favorevole. La fusion precedente della fraction tree
è un altro kernel e non viene conteggiata una seconda volta.

Il checker [c71_main_cell_screen.py](../../scripts/c71_main_cell_screen.py)
pinna l'hash della funzione e verifica dispatch, join, back-edge,
assenza di branch nei segmenti contati e moltiplicandi register×register.
Una ricompilazione diversa fallisce chiusa e richiede nuovo controllo.
Riproduzione locale senza GPU, dopo la compilazione statica documentata:

```sh
PATH=/tmp/c71-cuda-12.9.1/toolkit/bin:$PATH \
  /tmp/c71-cuda-12.9.1/toolkit/bin/cuobjdump --dump-sass \
  /tmp/c71-integrated-kernels-sm90.o > /tmp/c71-integrated-kernels-sm90.sass
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/c71_main_cell_screen.py \
  /tmp/c71-integrated-kernels-sm90.sass
```

L'analisi del CFG conta istruzioni **dinamiche per attraversamento** dei
rami nel loop, non istruzioni statiche moltiplicate indiscriminatamente
per i gate. Il cammino Copy contiene 66 `IMAD.WIDE.U32`, And/Xor 249,
e il tail selettore per programma 216; tutti quelli contati sono non
predicati. Scartando persino i moltiplicatori immediati restano
rispettivamente **54 / 205 / 180**. Pertanto, per A/X/C gate eseguiti e
P coppie programma/cella, il numero di risultati moltiplicativi soddisfa:

```
I >= 205*(A+X) + 54*C + 180*P
  >= 24*(7*(A+X) + 2*C + 6*P)
   = 24 * prodotti_Fp3_censiti.
```

Il circuito EXP30 usa realmente `compile_ratio(14)`; la sua cardinalità
non dipende dal fixture RMS a scale zero o dalla calibrazione dei pesi.
Le coppie supportate sono l'unione pubblica dei residui MSB delle celle
causali, conteggiata da `ratio_supported_pair_total`; ogni kernel esegue
il loop dei gate della rispettiva voce esattamente una volta. Non è
necessario materializzare la lista canonica per calcolare la cardinalità.
Questa è la schedule nominata; una specializzazione che salta o sostituisce
quei prodotti richiede una nuova analisi e non eredita automaticamente
questo NO-GO.

La [descrizione NVIDIA di Hopper](https://developer.nvidia.com/blog/nvidia-hopper-architecture-in-depth/)
riporta 132 SM e 64 core INT32/SM per H100 SXM. Il passaggio al ceiling
per `IMAD.WIDE.U32` e il clock ≤2 GHz sono condizioni esplicite dello
screen, non un service-rate misurato o una promessa del provider.

Sotto il tetto già dichiarato di 132 SM × 64 risultati scalar
INT-multiply/ciclo/SM × 2 GHz = **16.896.000.000.000 risultati/s**, applicato
alle istruzioni del binario, si ottiene:

| O | Prodotti Fp3 EXP30 | Lower dei soli coefficienti EXP30 |
|---:|---:|---:|
| 0 | 9.501.309.089.555 | 13,496178 s |
| 150 | 28.371.308.393.733 | 40,300154 s |
| 300 | 47.241.202.900.983 | **67,103981 s** |

A O=300 `T_proof_only >=67,103981 s` e quindi
`T_response_total = T_inference + T_proof_only >=67,103981 s`, con
`T_inference >=0` non misurato. Il lower non include RMS, inferenza,
ricostruzione/auth A/KV, range, PCS, PCG, serializzazione o HBM. Sono
costi positivi omessi, non assegnati a zero nel ledger. Nessun overlap
può rendere questo singolo lavoro più breve del proprio lower aritmetico.
Non serve completare un upper o il picco fisico per respingere il backend.

È **NO-GO della costruzione con questo main-cell scalare**, non lower
universale su B12 né impossibilità di ogni schedule a 512 replay. Vale
per il mapping pubblico e il codice/toolchain censiti; nuovo codice,
Tensor Core, packing o una riduzione algebrica richiedono un nuovo
certificato. La minima alternativa utile deve cambiare lavoro o risorsa
aritmetica. Con gli altri lower nominati della schedule seriale invariati,
a O=300 restano meno di 8,249 s per tutti i costi omessi: servirebbe già
oltre **8,13×** di riduzione su questo lower EXP30, prima di RMS e degli
altri costi. La sola eliminazione di riletture o del workspace non basta.
Nessun nuovo censimento ABI, pod o spesa è richiesto per questo esito.

## Due alternative strutturali EXP30

L'incarico limita la ricerca a due vie. Il codice dello
[screen](../../scripts/c71_exp30_alternatives.py) e i
[tre controlli ridotti](../../tests/test_c71_exp30_alternatives.py) non
modificano il verifier. Il [record pulito](evidence.md#two-structural-exp30-alternatives)
conserva i risultati e i conteggi. Non si riaprono Tensor Core o port scalari a
fattore costante. Le fonti primarie sono LogUp/GKR
([ePrint 2023/1284](https://eprint.iacr.org/2023/1284),
[copia locale](../../sota/2023-1284-logup-gkr.md)) e il GKR Boolean a pattern
([ePrint 2025/717](https://eprint.iacr.org/2025/717),
[copia locale](../../sota/2025-717-gkr-boolean-circuits-sublinear-ram.md)).
Il secondo paper cambia rappresentazione con un polinomio univariato:
**non** se ne importa il protocollo o il benchmark. L'adattamento sotto,
che mantiene i round multilineari, è una derivazione locale.

### 1. Rapporto dedicato con residuo intero e range

Massimo, differenze, lookup D→E, istogrammi e somma Z rimangono quelli
originali. Si sostituirebbe soltanto il circuito ratio da 94 livelli e
89.167 gate/copy complessivi. Per ogni cella causale:

```
r = 2^14 E - Pi*Z
delta = Pi mod 2
u = Z - 2r - delta
v = Z + 2r - delta
```

Con `0<=E<=2^30`, `2^30<=Z<=450*2^30`, `0<=Pi<=2^14`,
`delta in {0,1}` e parità autenticata, `0<=u,v<2^40` è equivalente
a RNE, inclusi entrambi i tie-even. I bound rendono le identità intere:
`Pi*Z<2^53`, quindi le discrepanze restano molto sotto p; non basta
verificare uguaglianze modulo p senza range. Le due slack e la parità
vanno collegate agli stessi byte E/Z/Pi, con forme autenticate,
commitment/masking e range batch dell'intera risposta. Non si fanno proof
per token e non si aprono residui o istogrammi privati.

In precisione variabile b, la candidata elimina i prodotti Boolean
quadratici del predicato squared-RMS: O(N b) vincoli bit/range e O(N)
prodotti di campo invece dell'espansione O(N b²) del moltiplicatore
scolastico, esclusi costo del prover range e nuovi endpoint. A b fissato
entrambe sono lineari in N: non si promette un prover sublineare nel
numero delle celle. Le slack sono nuovi witness da autenticare; il
range byte di A già pagato non ne dimostra automaticamente la validità.

L'istogramma D/E esistente non include Z o Pi né la posizione. Il check
usa `E=(2^30,2^29)`, `Z=3*2^29`: Pi corrette `(10923,5461)` e scambiate
hanno lo stesso istogramma E e la stessa somma Pi, ma solo le prime
soddisfano il rapporto. Una tabella per `(E,Z,Pi)` dipendente da Z privato
richiederebbe a sua volta prova di correttezza e legame posizionale.
Il protocollo LogUp non fornisce quel legame gratuitamente.

**Esito:** candidata semantica concreta, ma incompatibile con il
transcript ratio vigente (`gkr::Proof`, numero di round, consumo MAC e
FS). Non è selezionata sotto il vincolo di transcript invariato. Per
adottarla servono decisione esplicita sul nuovo protocollo e dimostrazioni
compositive, senza cambiare trust o garanzie. L'analisi non autorizza tale
sostituzione.

### 2. Aggregazione pesata dei pattern Boolean per layer

Sia c=(j,k) la cella in ordine MSB, con i primi t bit in j e B=2^t.
Per il layer di circuito corrente, ciascun wire Boolean è un pattern
di B bit; il selettore originale è `Eq(r_prefix,j)*Eq(r_suffix,k)*U(j,k)`.
Nei primi quattro bit si raggruppano layer del modello, conservando
head/query/key nel suffisso: la causalità è identica per ogni j e U
dipende solo dal padding pubblico dei 60 layer in 64 slot.

Si costruiscono istogrammi interni pesati da
`gate_weight*Eq(r_suffix,k)`, distinti per pattern e maschera U. AND
contribuisce al termine XY; XOR a X+Y−2XY; Copy a X. Il pattern da 16
bit è diviso in due da 8: `X*Y=sum_(a,b) X_a*Y_b`, quindi bastano quattro
tabelle di coppie, non una tabella da 2^32 righe. I bit nei layer dummy
sono zero pubblico; per B=16 ci sono 15 layer vivi per gruppo e una
sola U, con tessere da 8 e 7 bit effettivi.

Per ogni sfida precedente nota si valuta la stessa MLE del pattern.
Per il round corrente si somma sui restanti bit Boolean di j e si
moltiplica per il selettore MLE di U. La distributività ricostruisce
esattamente il cubico originale, compresi i prodotti incrociati fra
prefissi; non si moltiplicano medie e non si perdono pesi posizionali.
La sfida corrente arriva dopo gli stessi quattro coefficienti e MAC.
I bin si costruiscono prima delle sfide dei t round e non sono comunicati.
Il controllo confronta i cubici a quattro punti base e uno non-base,
con prefissi 0, 1 e non-base, AND/XOR/Copy, padding e più suffissi.

Per S=N*G voci gate/cella del layer, blocchi B=2b e sotto-pattern di b bit
richiedono O(S/B + M*B*2^(2b)) operazioni di campo, con M maschere
pubbliche distinte, più generazione packed dei bit e coda su N/B righe.
Anche usando M<=2^B, scegliendo b proporzionale a log S con costante
abbastanza piccola la parte di campo è O(S/log S), non una sola riduzione
costante; il termine tabellare è allora O(B*2^(4b)). La geometria concreta
B=16 ha M=1. È un bound parametrico **del consumer**: il
riferimento Python legge bit scalari, e il replay canonico non eredita
questa complessità. Non è una compressione garantita dei dati privati.
Il bound riusa le valutazioni MLE di ciascun sotto-pattern fra i bin;
l'oracolo Python le ricalcola per semplicità e non ne è un'implementazione
efficiente. Le tabelle di produzione devono avere cap pubblico: numero
di pattern presenti e occupazione privata non entrano nel transcript.

Per la prima variante B=16, b=8, prima della fattorizzazione dei pesi sotto:

| O | Blocchi pubblicamente supportati | Prodotti Fp3 per pesi bin | Addizioni Fp3 ai bin | Lower della sola coda scalare, s |
|---:|---:|---:|---:|---:|
| 0 | 1.449.600 | 129.256.483.200 | 520.818.086.400 | 0,852443 |
| 150 | 4.329.600 | 386.057.443.200 | 1.555.556.006.400 | 2,536417 |
| 300 | 7.209.600 | 642.858.403.200 | 2.590.293.926.400 | 4,220242 |

Le addizioni non includono i raddoppi XOR (32.168.073.600 /
96.078.153.600 / 159.988.233.600), valutazione dei bin, producer/replay, fold,
riduzioni fra worker, MAC/FS e PCS. Nessuno di questi costi vale zero.
Il payload dei bin è **3.548.160 B** per un layer di circuito; non è il
workspace completo né una misura allocata/riservata. Repliche per worker
e contesa possono dominare. Un aggiornamento logico non viene convertito
in traffico HBM: il riuso in cache va provato, non assunto.

La coda riusa il kernel scalare certificato e le sue condizioni hardware;
il lower 24 IMAD/prodotto non viene attribuito al nuovo codice dei bin.
La variante B=8 lascia invece 8,412492 s di sola coda a O=300: con il
restante lower seriale nominato 56,751469 s è già esclusa quella
combinazione, anche gratis per i bin. B=16 lascia circa 4,028 s dopo
quei due lower, **non** un budget garantito: mancano ancora RMS, inferenza
e altri lavori. La prima costruzione dei pesi bin avrebbe richiesto oltre
159 miliardi di prodotti Fp3/s se tutto quel residuo fosse disponibile;
tale conteggio è superato dalla fattorizzazione seguente.

**Esito:** candidata a transcript invariato, ora portata nel controllo
nativo ridotto con pesi posticipati. Il vecchio NO-GO non la esclude, ma nessun
upper completo, GO entro arena o tempo ≤65 s è dimostrato. Nessuna GPU
o spesa, e nessuna terza alternativa aperta.

### Pesi di gate applicati dopo l'istogramma

Validazione: [record nativo su SHA pulita](evidence.md#native-exp30-late-gate-weights).

Il fattore `weight_g*Eq(k)` non deve essere formato per ogni coppia.
Il [prover nativo](../../rust/volta-pcs/src/c71_matrix/rms/gkr/patterns.rs)
mantiene temporaneamente l'asse dei gate:

```
H_g[a,x,b,y] = sum_k Eq(k) * [pattern_g,x(k)=x, pattern_g,y(k)=y]
H[a,x,b,y]   = sum_g weight_g * H_g[a,x,b,y]
```

Ogni prodotto col peso si paga una volta per slot della tabella, inclusi
gli slot zero, invece che per blocco sorgente. Per XOR si ottengono X e Y
dai margini di una sola tessera della controparte; non si costruiscono
istogrammi lineari durante la lettura. Copy conserva il solo marginale.
Nessuna media sostituisce prodotti, nessun istogramma viene pubblicato e
nessuna correlazione entra nel modulo. Cap e tessere sono pubblici.

Con 15 layer vivi per gruppo, le tessere **5+5+5** hanno 96 indici totali:
9.216 bin per gate AND/XOR e 96 per Copy. Tutti i gate del layer di circuito
restano residenti insieme: nessun nuovo replay per gate o banda di gate.
Le tessere 8+7 richiederebbero **7.025.236.992 B** di soli istogrammi raw
al layer massimo, già oltre arena. Il massimo raw selezionato è invece
**661.723.776 B**, più 223.488 B per l'aggregato.
Sono 441.149.184 B di limb bassi e 220.574.592 B di riporti u32;
le somme intere rinviano la riduzione modulare a una sola volta per bin.
Ogni aggiornamento paga tre somme u64 e tre aggiornamenti dei riporti u32;
le riduzioni base finali sono 1.286.784.576 per risposta.
Il bound pubblico sulle posizioni suffix impedisce overflow a 96 bit.

| O | Vecchi prodotti peso×posizione | Prodotti peso posticipato | Prodotti Eq posizione | Aggiornamenti interi dei bin | Gate word con replay precedente |
|---:|---:|---:|---:|---:|---:|
| 0 | 129.256.483.200 | 428.928.192 | 1.577.058.116 | 788.667.926.400 | 1.858.538.621.952 |
| 150 | 386.057.443.200 | 428.928.192 | 3.154.116.420 | 2.355.557.846.400 | 5.477.798.043.648 |
| 300 | 642.858.403.200 | 428.928.192 | 3.154.116.420 | 3.922.447.766.400 | 9.098.344.541.952 |

Eq posizione è generato incrementalmente senza divisioni, anche con sfide
0/1, con una pila O(log N). La riduzione paga inoltre 565.269.696
addizioni/sottrazioni e 204.512.256 raddoppi XOR. La valutazione densa dei
cubici censita paga 91.285.468 prodotti Fp3, più 2.820 per i selettori dei
prefissi, su ciascuna risposta. Questi lavori restano distinti dai 428,93
milioni di prodotti dei pesi: non si presenta il loro totale come nullo.

Il producer impacchetta quattro gruppi da 16 nelle stesse word u64 prima
del replay. Il conteggio include la rigenerazione fino al livello
richiesto, non solo i gate di quel livello. Una cache privata conserva E/Pi per cella causale e Z per riga,
confrontati byte per byte con gli originali anche sul padding. Il fill
legge 132.192.000 / 391.392.000 / 650.592.000 byte sorgente per O=0/150/300.
Le successive 94 letture per cella del prefisso sono dalla cache: a O=300
10.165.536.000 frame e 121.986.432.000 byte logici. Non implicano più
ricostruzione numerica a ogni frame; non eliminano il replay Boolean.
Il fill non garantisce da solo una sola esecuzione di ogni producer numerico.
Tutto questo appartiene a `T_proof_only`. I 282.416.239.180.800 byte logici
di read/modify/write dei bin **non sono traffico HBM**: cache, staging,
collisioni e riduzioni CUDA restano da progettare/misurare.

Nel [piano arena](../../scripts/c71_arena_plan.py) gli istogrammi vengono
dopo la fence delle cache lookup e prima dell'obbligo byte finale. Il raw
è rilasciato dopo l'applicazione dei pesi; l'aggregato dopo il quarto
cubico, prima della coda GKR. Il live nominato dell'evento è
1.615.545.088 / 1.914.070.016 / 2.212.591.616 B, inclusi il replay DAG e la cache
originale trattenuta fino all’endpoint byte. Non aumenta il massimo
nominato del commit A e conserva il margine nel piano; allocator,
workspace completi del getter e staging GPU restano obblighi espliciti.
Il cap 1 GiB della funzione nativa è locale, non un'ammissione dell'arena
complessiva né un'autorizzazione a spill.

La prova a 32 celle confronta l'intero wire con i prover sourcewise e
denso, punto, endpoint originale, consumo MAC e FS dopo quattro round,
con padding e prosecuzione fino a range/PCS. Il runner integrato O=0 usa
ora questo percorso EXP30; la proof positiva conserva 88.049 MAC ideali.
Il primo fixture impegnava byte non nulli nelle celle dummy: la PCS lo
ha respinto dopo parità dei wire GKR. Il secondo fault di input violava
già il piccolo circuito, invece di isolare il legame PCS: corretto anche
questo fixture, senza allentare i controlli.

Il lower della coda scalare resta 0,852443 / 2,536417 / 4,220242 s.
Non si attribuisce il ceiling IMAD del vecchio kernel ai nuovi bin, né
si convertono conteggi Boolean/addizioni in un upper H100. I tre tempi
`T_inference`, `T_proof_only`, `T_response_total` restano distinti e non
misurati su hardware target. La prossima fase dominante è il consumer
degli istogrammi insieme al producer packed; non altri censimenti ABI.

La variante con riporti e cache è verificata nel
[record nativo su SHA pulita](evidence.md#native-exp30-wide-accumulators-and-original-cache).
I conteggi restano un modello sorgente, non istruzioni CUDA o un upper H100.

### Replay EXP30 con alias e antenati condivisi

Il DAG interno di valutazione sostituisce il replay packed per livelli,
conservando i wire originali usati dall’istogramma. Copy non esegue una
operazione Boolean; zero, uno, identità e gate commutativi identici sono
risolti dalla forma pubblica. La selezione all’indietro elimina gli
antenati non usati. Nessuna scelta dipende da witness o correlazioni.
Non si semplificano i polinomi GKR dopo il fold.

| O | Operazioni word precedenti | Operazioni word DAG | Gather dei wire originali |
|---:|---:|---:|---:|
| 0 | 1.858.538.621.952 | 996.381.255.680 | 32.997.687.296 |
| 150 | 5.477.798.043.648 | 2.936.702.648.320 | 97.256.341.504 |
| 300 | 9.098.344.541.952 | 4.877.714.055.680 | 161.537.847.296 |

Il replay diminuisce del 46,39%; non cambiano i 3.922.447.766.400
aggiornamenti dei bin a O=300, i prodotti dei pesi o la coda scalare.
Un solo piano del livello richiesto vive durante il prefisso. Piano,
input, valori intermedi e vettore originale selezionato richiedono al
massimo 1.943.984 B nel riferimento nativo, senza il transitorio del
compilatore pubblico. Il compilatore viene eseguito una volta per livello,
non per gruppo di celle. Il DAG è liberato prima della valutazione dei cubici.

I 117.065.137.336.320 B logici di lettura di due operandi e scrittura del
risultato a O=300 non sono un lower HBM. Restano da definire mapping CUDA,
residenza dei valori e parallelismo. Il conteggio word non è un conteggio
di istruzioni macchina né garantisce uno speedup. Tutto il replay resta
in `T_proof_only`; `T_inference` e `T_response_total` non ricevono nuovi
upper o crediti. Il requisito totale resta 65 s; nessun GO alla spesa.

Il [record del DAG nativo](evidence.md#native-exp30-replay-dag) verifica
questi conteggi sui piani pubblici effettivi e la parità nel percorso ridotto.

### EXP30 momenti binari BMMA

[Record del componente](evidence.md#exp30-bmma-component) e
[packing/riduzione con parità nativa](evidence.md#exp30-moment-pipeline), su SHA pulita.

La candidata sostituisce i bin privati del prefisso con momenti pesati,
conservando i quattro cubici originali. Posto `w_k=Eq(r_suffix,k)`, per
ogni limb canonico l e bit b calcola
`C[g,i,j,l,b]=sum_k X[g,i,k] Y[g,j,k] bit_b(w_k[l])`.
Poi ricostruisce `sum_b 2^b C`, riduce modulo Fp e applica il peso del gate
una volta. Il conteggio conserva la posizione tramite Eq; nessun
istogramma privato o momento viene inviato. Una riga/colonna costante
produce i margini XOR, esclusa dal selettore originale. Per i Copy si
calcola direttamente la matrice Eq_bit×wire, raggruppando 16 bit di Eq e
8 colonne wire/posizione: nessun aggiornamento wide sparso residuo.

Il [componente CUDA](../../cuda/c71_exp30_bmma.cu) usa
`mma.sync.aligned.m16n8k256.row.col.s32.b1.b1.s32.and.popc` e le
[mappe PTX ufficiali](https://docs.nvidia.com/cuda/parallel-thread-execution/index.html#warp-level-matrix-fragment-mma-168256).
Il compilatore locale 12.9.86 emette BMMA native per sm_90, con zero stack,
spill: 70 registri per And/Xor, 40 per Copy. I due kernel di riduzione
usano 32 registri ciascuno; packing Eq 32, trasposizione wire 18 e 512 B
shared per CTA. Solo quest’ultima richiede una barriera locale. Sono compilazioni
statiche sul toolkit temporaneo già documentato, non esecuzioni H100.
I test host emulano la disposizione collettiva dei frammenti e confrontano
le somme intere originali, con valori vicini a p, padding e tile parziali.
Il test algebrico verifica tutti i cubici del prefisso, maschere pubbliche
multiple e sfide 0/1/non-base. Il riferimento nativo con tile di un bit verifica anche la parità con
proof, FS e MAC originali. È un oracolo dei momenti, non l’adapter CUDA.

Schedule proposta: un livello di circuito per volta; batch di al più
16.384 posizioni suffix, 64 tile da 256. Il producer emette una sola
finestra di bitplane, poi una fence precede i consumer; questi completano
prima di riusare la finestra. I contatori restano vivi tra i batch e sono
ridotti dopo l’ultimo. Il producer emette quad da quattro posizioni ×
16 righe; ogni tile si traspone sul posto dopo aver salvato i suoi 512 B
in shared memory. Non si alloca un secondo stage globale. Eq si impacchetta come `[tile][word][bit]`, con load
vettoriali a 128 bit per ridurre le istruzioni, senza ridurre i byte logici.
Gli indici originali restano necessari: compattare il supporto non permette
di usare Eq del rango compatto. N massimo è 7.209.600, quindi nessun
contatore s32 può traboccare; la somma ricomposta occupa meno di 96 bit.

| O | BMMA warp And/Xor | BMMA warp Copy | Batch per livello | Lower parziale AND-mask, s |
|---:|---:|---:|---:|---:|
| 0 | 100.233.469.056 | 5.491.184.580 | 89 | 0,189836 |
| 150 | 299.355.229.056 | 16.399.859.580 | 265 | 0,566961 |
| 300 | 498.476.989.056 | 27.308.534.580 | 441 | 0,944085 |

Il lower concede favorevolmente 132 SM, clock ≤2 GHz e 128 risultati
bitwise/ciclo/SM e conta solo i due AND a 32 bit per lane e BMMA And/Xor.
Non trasferisce ai LOP3 il vecchio bound IMAD, non conta i BMMA come singole
operazioni scalari e non assegna loro un throughput non misurato. Il lower
HBM dei soli contatori fra batch, concedendo 256 MiB di cache trattenuta e
3,35 TB/s, è 0,031827 / 0,095482 / 0,159137 s. Si riporta separatamente;
il massimo dei due è un lower valido senza assumere overlap o costruire
un upper dalla banda. Il lower congiunto completo resta aperto.

A O=300 i load/store logici dei contatori costano circa 8,43 TB, quelli
A/Y circa 47,85 TB e quelli Eq circa 127,61 TB, oltre a Copy e staging.
**Non sono traffico HBM misurato**: il riuso di Eq e degli operandi va
verificato. Restano 11.349.900 prodotti Fp3 dei pesi (i due margini XOR sono sommati
prima dell’unico prodotto), ricostruzione dei
conteggi, trasposizione/packing, gather, producer e coda scalare; nessuno
riceve tempo nullo. Il [ledger](../../scripts/c71_exp30_bmma.py) separa
queste voci e conserva gli obblighi mancanti.

La variante `exp30_bmma=True` del [piano arena](../../scripts/c71_arena_plan.py)
riserva separatamente stage wire, Eq, contatori And/Xor, contatori Copy,
mappa gate, piano replay, momenti canonici e aggregato. Dopo l’ultima
fence BMMA libera stage/Eq/replay prima di allocare i momenti; dopo la
fence di riduzione libera i contatori. Il payload massimo nominato è
489.850.540 B nella variante con producer condiviso ed Eq fattorizzata,
con riuso dopo fence a ogni livello. Il precedente componente isolato
riservava 490.859.484 B. La cache E/Pi/Z resta
viva fino all’endpoint byte. I layout censiti mantengono 256 MiB di margine;
questo non include ancora transitori completi, allocator e port CUDA.
Il backend nativo selezionato resta quello a istogrammi finché non è
verificato il nuovo collegamento completo. `T_inference`, `T_proof_only`
e `T_response_total` restano distinti e senza upper H100; target totale
65 s. Nessun pod o spesa è ammesso da questi controlli.

Il ledger del packing conta ora Eq per tutti i 94 livelli: il precedente
record componente ometteva questo fattore nel solo campo
`Eq_stage_write_bytes`. Il nuovo conteggio distingue input canonici,
voti warp, store Eq, lettura/scrittura della trasposizione e output dei
momenti. I vecchi record restano immutati; nessun tempo è dedotto da
questi byte logici.


#### Producer condiviso e Eq originale

[Record dei controlli su SHA pulita](evidence.md#exp30-shared-producer).

Il DAG pubblico è pianificato per dipendenze: nessuna scrittura del livello
può coincidere con un suo operando, e gli slot si riciclano dopo barriera.
Il checker nativo e quello C++ confrontano tutti i 95 livelli, con live mask
piena/parziale/vuota. Il fixture binario pubblico si genera con
`C71_EXP30_SHARED_FIXTURE`; non contiene witness canonici. Per i 94 livelli
producer servono al massimo 737.856 B di piano e 39.792 B shared per CTA,
senza storia intermedia globale. Il kernel usa 128 thread/CTA e 32 registri,
zero stack/spill. Carica direttamente i byte originali E/Pi/Z e scrive il
layout quad del packing in-place. Non materializza altri A o Snapshot.

La nuova compattazione attraversa anche i confini delle righe: il lavoro
Boolean diventa 976.802.088.000 / 2.917.468.488.000 / 4.858.134.888.000
word-op, per O=0/150/300. I trasferimenti host→device dei piani pubblici
costano 43.500.836 B per risposta, oltre a mappe/pesi; la cache originale
resta sul device. Il ledger distingue 24.527.232.000 / 73.256.832.000 /
121.986.432.000 B di load logici E/Pi/Z, traffico shared, istruzioni ballot
e 1.618.116.000 / 4.832.916.000 / 8.047.716.000 barriere CTA. Queste ultime
non hanno ancora service-rate misurato e non ricevono tempo nullo.

Eq viene valutata sul suffix originale tramite due mezze tabelle, poi
fusa con il packing bitplane. Tabelle e punto riservano 197.184 B, senza
un buffer Eq canonico per batch né trasferimenti esterni per batch.
Il costo include un prodotto Fp3 per posizione/livello e la costruzione
delle tabelle; i controlli CPU includono sfide 0/1/non-base e confini di
riga/batch. I kernel Eq-table/Eq-pack usano 38/40 registri; il kernel pesi
usa 48 registri. Tutti senza stack/spill. L’aritmetica Fp3 è condivisa con
il kernel range già verificato, la cui regressione host passa.

La riduzione produce momenti canonici prima di rilasciare i contatori;
pesi e flag sono allocati dopo quel rilascio. Il controllo CPU attraversa
packing→conteggi→riduzione→pesi e confronta somme dirette Fp3. Il raccordo dei 240 momenti canonici al prefisso nativo passa il
confronto proof/FS/MAC, inclusi quadratici non nulli e rifiuti di codec.
Resta da lanciare/verificare CUDA: non è una proof GPU positiva. I lower completi, il picco fisico e le tre metriche
temporali restano aperti; nessuna autorizzazione H100 o spesa.


Il raccordo finale usa 5.760 B device→host per livello, 541.440 B per
risposta. Il prefisso compatto usa 2.318.698 prodotti, 1.362.060 somme e
25.004 sottrazioni Fp3 sui 94 livelli, inclusa Eq del selettore e dei
prefissi. Sono lavoro nativo e trasferimento della prova, non inferenza
né byte del certificato. La produzione nativa selezionata rimane a tile
cinque bit; il decoder candidato viene attraversato dal riferimento a
momenti e dalla continuazione originale nel test ridotto.

### Original byte tree coefficient screen

[Record del raccordo e del lower](evidence.md#native-moment-seam-and-byte-tree-screen).

Lo [screen del binario](../../scripts/c71_byte_endpoint_screen.py) considera
il port letterale della fraction tree byte con la LUT originale. La LUT
non riduce le coppie visitate dai round: per `v=cell_bits+4` e otto livelli,
`sum(h=0..7, 2^(v+h)-1)=255*2^v-8`. Sono 547.608.330.232 coppie a O=0
(v=31) e 1.095.216.660.472 a O=150/300 (v=32). Non si somma questo costo
agli stessi coefficienti di un altro ledger: il main-cell EXP30 è qui
interamente omesso.

Il kernel fattorizzato già compilato usa 774 IMAD.WIDE.U32 non predicati,
con entrambi i moltiplicandi in registri, per coppia attiva. Il controllo
minimo aggiunge `c71_byte_coeff6`, con gli stessi 18 prodotti Fp3 e sei
prodotti base per Fp3: il numero scende a **525**, con 130 registri e zero
stack/spill. Il confronto host contro il cubico diretto passa. Il parser
lega il conteggio all’hash delle istruzioni, controlla guard/uscita e
assenza di rami/call nel corpo; rifiuta un binario cambiato. Non addebita
load/store o overhead per ciascuna moltiplicazione inlined.

Condizioni: 132 SM, clock ≤2 GHz, al più 64 risultati scalar INT multiply
per ciclo/SM applicabili a IMAD.WIDE.U32, stesso kernel, una visita per
coppia e schedule seriale nominata. Il ceiling è 16.896.000.000.000
risultati/s. Il campo sotto usa la variante più favorevole a sei prodotti:

| O | Lower coefficienti byte, s | Lower disgiunto range/commit/prime aperture, s | Lower parziale T_proof_only e T_response_total, s |
|---:|---:|---:|---:|
| 0 | 17,015529 | 32,721968 | 49,737497 |
| 150 | 34,031057 | 36,085131 | **70,116188** |
| 300 | 34,031057 | 39,684627 | **73,715684** |

`T_inference >=0` rimane non misurato. Il lower omette tutta l’inferenza,
getter/replay/auth, RMS, main-cell EXP30/BMMA, rigenerazione/fold byte,
PCG, WHIR restante, MAC/FS e serializzazione. Sono costi positivi omessi,
non dichiarati nulli. La somma è fra fasi distinte della schedule seriale;
nessun overlap e nessun upper derivato dalla banda. La variante a nove
prodotti dà invece 57,807719 / 86,256632 / 89,856128 s per le stesse fasi.

**NO-GO della costruzione con questo port letterale**, già a O=150/300;
non serve un ledger completo per respingere un sottoinsieme che supera
65 s. Non è un lower universale sulla relazione: contrazione dell’asse
pubblico dei nodi, struttura polinomiale del byte o altro mapping cambiano
le premesse e richiedono un nuovo screen. La priorità locale diventa quel
controllo strutturale. Nessun H100/pod/spesa; il goal fisico resta aperto.

### Original byte node contraction

La [candidata locale](../../scripts/c71_byte_tree_contraction.py) contrae
il selettore pubblico originale dei nodi prima dei round cella. I figli
sono polinomi nel byte di grado D=2^(7−h): una base di dimensione
min(4·2^h,D+1) contiene la forma quadratica originale. La somma delle
dimensioni è **64**, contro **1.020** funzioni figlio. Il lavoro cella
passa da O(N·B) a O(N·sqrt(B)) rispetto all'alfabeto B; setup pubblico
e recupero terminale sono separati. Nessun costo è dichiarato gratuito.

Il test algebrico confronta tutti i cubici su piccoli alfabeti, sfide
non Boolean/0/1, matrici singolari e padding pubblico. Un istogramma
pesato al punto cella finale ricostruisce anche le direzioni eliminate
dalla forma: omettere quel replay sarebbe scorretto. Il padding EXP30
usa una baseline byte zero pubblica, conservata analiticamente, e le
12 lane vive. Eq resta sugli indici originali.

Il piano mantiene nove round streaming. Una LUT pubblica prepesata
per lane elimina i prodotti campo durante la rigenerazione dei singoli
valori; il ledger conserva costruzione delle LUT, letture e somme.
La variante corrente prepesata mantiene f e d·f: il costo LUT/fold
raddoppia, mentre il ciclo dei coefficienti scende da cinque a tre
prodotti Fp3 per feature. Eq dell’asse corrente viene applicato dopo la
somma globale; il suffix Eq richiede tre prodotti per coppia.
Al checkpoint la LUT massima occupa 106.954.752 B; un batch di 16.384
coppie occupa al più 26.738.688 B, oltre a indici/Eq. Questi buffer sono
rilasciati con fence prima dei fold successivi. Non si presume residenza
in cache o fold in-place: destinazione e sorgente sono disgiunte.

| O | Stato al checkpoint, B | Massimo dei due stati, B | Indirizzo massimo catena EXP30, B | Massimo di tutte le catene note, B |
|---:|---:|---:|---:|---:|
| 0 | 443.577.600 | 665.366.400 | 2.082.995.968 | 6.087.512.576 |
| 150 | 1.324.857.600 | 1.987.286.400 | 3.370.001.152 | 6.126.837.504 |
| 300 | 2.206.137.600 | 3.309.206.400 | 4.964.490.752 | 6.166.159.104 |

Il massimo globale nominato resta range A. Il margine peggiore è
276.291.840 B, appena 7.856.384 B oltre i 256 MiB richiesti: non autorizza
workspace ulteriori impliciti. Cache E/Pi/Z, LUT byte originale e slot
persistenti restano vivi; il checker nativo controlla indirizzi e fence.
Il piano riserva anche feature/diagonali, supporti, scratch pubblico da
1 MiB e recupero dei figli. Sono payload pianificati, non capacità
native o misura del picco fisico.

I soli coefficienti delle coppie supportate richiedono al più
60.160.281.120 / 179.641.128.672 / 299.121.312.672 prodotti Fp3.
Il [report](../../scripts/c71_byte_tree_contraction.py) separa fold,
LUT, rigenerazione, recupero e coda lane/nodo. Restano setup pubblico,
baseline/Eq, istruzioni e traffico completi: non eredita il lower del
kernel scalare respinto. `T_inference`, `T_proof_only`, `T_response_total`
non hanno nuovi upper; replay e recupero appartengono alla prova.
Il confronto Fp3 nativo con la stessa LUT passa sui 256 byte, otto
livelli e due lane, anche dopo fold non Booleani. Recupera i figli
originali tramite istogramma privato. Il successivo raccordo alla proof
passa con wire/FS/MAC identici, rigetti sull'endpoint originale e positivo
integrato lookup/GKR/WHIR. Quest'ultimo usa 76 round custom e otto
terminali; il certificato è di circa 7,75 MB con 88.049 MAC ideali originali.
La dimensione e il receipt possono variare con le monete dell'installazione;
la parità byte per byte dei componenti usa lo stesso fixture e le stesse monete.
Il riferimento è limitato a domini completi ≤128 celle e viene selezionato
nel caller EXP30 a pattern solo in tale ambito. Passa ora anche il getter
a batch con LUT prepesate, baseline pubblica, chiavi compatte e checkpoint,
fino alla stessa proof integrata. Il controllo ragged rifiuta prima di
leggere la sorgente o consumare righe/sfide. Il caller passa ora gli
intervalli canonici: 288.000 righe causali, con 23.209.985 / 69.305.991 /
115.401.741 coppie supportate sommate sui round, coincidenti col ledger
a ogni round. Prima del checkpoint si iterano intervalli; gli indici
espliciti appartengono soltanto allo stato compatto. Le lane private sono
12, le altre quattro restano nella baseline pubblica. Le due tabelle Eq
del recupero occupano 589.824 / 786.432 / 786.432 B, vivono con
l’istogramma e sono rilasciate prima del fold dei figli: il massimo
del piano non cambia. Restano lavoro/traffico congiunti e harness dei rate
ignoti; il guard ridotto non viene promosso a esecuzione canonica.
Gate di spesa **NO-GO**, goal locale in corso senza blocchi autorizzativi.


Il kernel `c71_byte_contract_coeff` riusa Fp3 originale e riduzione a
blocchi del microbenchmark range. Il controllo host confronta il cubico
con valutazioni dirette per tutti i ranghi, inclusi zero e sfide estese;
sm_90 compila con 94 registri, 24.576 B shared e zero stack/spill.
Lo [screen del binario](../../scripts/c71_byte_contract_screen.py) conta
1.315 istruzioni incondizionate per feature e 1.120 per suffix selector,
senza attribuire istruzioni di carico per ogni prodotto inlined.
Con slot fissi [4,8,16,17,9,5,3,2], dodici lane, 132 SM, clock ≤2 GHz e
al più quattro warp issue/ciclo/SM, il lower dei coefficienti è
0,767512 / 2,291823 / 3,816126 s. Sono disgiunti dal BMMA del prefisso,
dalla coda main scalare e dal lower getter/range/commit/prime aperture:
la somma parziale è **49,307409 / 57,370385 / 65,731923 s**.
Questo backend/schedule è **NO-GO a O=300**, anche prima di inferenza,
producer Boolean, rigenerazione/fold byte, PCG e PCS rimanente. Non è
un lower universale: slot adattivi, aritmetica diversa o nuove fusioni
richiedono un nuovo screen. I precedenti tentativi diretti sono conservati
come diagnostici dirty, non come misure o record di protocollo.
La riscrittura successiva delle primitive campo sostituisce quel backend:
`fp_add` seleziona la sottrazione di p se c’è carry oppure se la somma
senza carry è ≥p; `fp_sub` corregge il borrow con 2^32−1. Per il prodotto,
con hi/lo del prodotto intero, t=lo−(hi>>32) corretto modulo p e
u=(hi mod 2^32)·(2^32−1) soddisfano t+u≤2p−2, anche se t non è ancora
canonico. La stessa addizione restituisce quindi il rappresentante canonico.
Il device usa carry/borrow PTX espliciti secondo la
[specifica NVIDIA](https://docs.nvidia.com/cuda/archive/12.1.1/parallel-thread-execution/index.html#extended-precision-arithmetic-instructions);
il controllo host confronta con u128 modulo p ai bordi e su 4.096 coppie.
Non cambia campo, codec o transcript; l’esecuzione PTX resta da verificare
nel primo controllo GPU autorizzato.

Il binario carry ha 946 istruzioni per feature e 823 per suffix selector;
leaf-pair e merge6 scendono da 231/1.183 a **197/889**. Il checker lega
i quattro corpi compilati a digest e controlla anche i percorsi della coda
main: il lower di 24 risultati IMAD.WIDE/Fp3 resta valido. Il costo range
precedente è **sostituito**, mai sommato al nuovo; FFT e getter mantengono
le condizioni precedenti. I coefficienti byte danno 0,553281 / 1,652121 /
2,750955 s; la somma parziale congiunta diventa **45,267005 / 52,813136 /
60,657831 s**, ancora senza inferenza e le altre fasi indicate dal report.
Il kernel byte usa 96 registri, 24.576 B shared, zero stack/spill; anche
i dieci kernel BMMA condivisi compilano senza spill. I buffer arena non
cambiano. Non è un upper, un lower completo o un GO alla spesa.

La chiusura del ledger richiede il **Γ calibrato del modello reale**,
selezionato dal proprietario il 2026-09-26. Il census RMS a scale zero
non lo sostituisce. Il lavoro locale resta in corso; GPU e spesa non sono
autorizzate.


Sul solo Γ RMS sintetico a scale zero, riusando gli intervalli e i profili
pubblici del census esistente, il kernel main scalare certificato conta
377.460.232.230.821 prodotti Fp3: lower condizionale 536,165103 s.
Concedere gratis i primi 4/6/8/9 round cella lascia rispettivamente
**70,268864 / 19,887718 / 5,277466 / 2,638732 s** di sola coda;
la pre-elaborazione concessa gratis non è un algoritmo implementato.
I conteggi includono i selettori per ogni coppia/profilo/livello, non
soltanto le porte. Trasferire a RMS il solo prefisso EXP30 B=16 non
riapre quindi quel fixture. Non è un bound per Γ calibrati diversi o
per un nuovo prover non scalare. L'acquisizione del Γ selezionato precede
un ulteriore port specifico RMS e la chiusura dei relativi conti PCG.

### Real calibrated Gamma

Il proprietario ha confermato che Γ è **da calibrare**; non si attende un
manifest già prodotto. La ricerca locale del
2026-09-26 nel repository, nei progetti locali e nei percorsi temporanei
non ha individuato un manifest calibrato. Il
[contratto congelato](../../manifests/c7-d126-gemma31b-quant-requirements-v1.json)
ha `instantiated:false` ed esponenti/calibrazione non istanziati; resta
immutato. Il solo `benchmarks/weights/model.safetensors` contiene 160
tensori GPT-2 (controllato il solo header di 14.283 B), non i 772 tensori
Gemma. Non è stata acquisita alcuna copia del checkpoint reale.

Il raccordo minimo riusa [Recipes::compile](../../rust/volta-pcs/src/c71_matrix/gemma/profile.rs)
e il wrapper canonico: 772 esponenti W nell'ordine dei tensori pinned e
1.435 esponenti delle sorgenti A semantiche, identificati dal layout
ricompilato. La stessa mappa deve valere a O=0/150/300, con alias
embedding/head coerente ed e_Pi=-14. Servono i riferimenti del manifest
alla revisione del checkpoint, alla procedura/dati di calibrazione e ai
controlli numerici: la sola validità sintattica della mappa non dimostra
che sia calibrata. Il proprietario ha selezionato la prima calibrazione sul
**workload C7.1 fissato a O=0/150/300**, senza certificazione di qualità
generale e senza modificare le garanzie crittografiche. Si riusano i 100
token del [prompt pinned](../../manifests/c7-d126-gemma31b-workload-v1.json)
in ciascun tentativo; i 50 token successivi sono generati dalla relazione
intera, con il predecessore KV del tentativo precedente. Si conserva anche
il KV dell'ultimo token emesso, senza generare un token aggiuntivo.
Le regole correnti RNE/overflow reject, EXP30 e le
tabelle certificate restano quelle del design e della security; i campi
vuoti del contratto storico non riaprono quelle scelte.

Prodotto il profilo, si validano identità e scale, si ricompilano ricette
e tabelle attese nei tre contesti, quindi si sostituiscono nel ledger
i circuiti RMS e le riserve PCG dipendenti da Γ. Solo allora si rivalutano
lower congiunto e picco. I soli header del checkpoint non bastano:
occorrono i pesi reali e dati di attivazione per la calibrazione.
Non si avviano acquisizioni pesanti, calibrazione completa o GPU in questa
tranche. La ricerca della calibrazione è esterna al protocollo;
validazione/compilazione di Γ e tutto il replay durante la prova restano
contati secondo [security §1](security.md#1-enunciato-e-oggetti-fissati).

Il percorso minimo riusa i componenti esistenti, nell'ordine seguente:

1. **W reale.** Verificare i due shard pinned, derivare per ciascun tensore
   l'esponente minimo che soddisfa RNE e range simmetrico i16, poi produrre
   il packed nell'ordine dei terminali. L'[ingest](../../scripts/c7_d126_gemma_weight_ingest.py)
   verifica hash e minimalità degli esponenti forniti; il
   [componente Rust](../../rust/volta-pcs/src/gemma31b_bf16.rs) già scansiona,
   sceglie l'esponente e converte un tensore nel medesimo buffer. Il modo
   `pack --native-packer` ora collega quel componente all'ingest: il parent
   verifica gli header e fa SHA-256 degli stessi byte passati al worker,
   riceve esponente minimo e packed, scrive nell'ordine dei terminali e
   pubblica solo dopo i due hash completi e il controllo del file persistito.
   Gli esponenti ricavati e l'hash del binario sono nel report. Il
   [confronto Python/Rust](../../tests/test_c7_d126_gemma_native_bf16.py)
   copre anche più tensori, pipe oltre capacità, hash errati, non finiti,
   input troncati, worker assente e pulizia delle partial. Non è ancora
   un ingest del checkpoint reale né una misura di throughput. Gli shard occupano
   62.546.338.248 B, il packed 61.394.690.560 B: conservarli entrambi richiede
   123.941.028.808 B, esclusi temporanei. Il massimo tensore privato è
   l'embedding, 2.818.572.288 B; questi sono costi offline, non nuovo spazio
   nell'arena della risposta. Il modo nativo pianifica il massimo tensore
   più 512 MiB di margine host (3.355.443.200 B), con chunk Python da 4 MiB;
   richiede packed più 1 GiB libero oltre agli shard già presenti.
   Questo è un requisito operativo del tool, non un picco RSS misurato.
   Non si applicano i requisiti host storici del modo Python come lower
   inevitabili della calibrazione. Acquisizione ed esecuzione completa
   restano fuori dall'autorizzazione locale; i test non leggono pesi reali.
2. **A reale.** Raccogliere le statistiche delle sorgenti semantiche sui
   dati scelti, mantenendo identità dei produttori e posizioni KV. Le
   statistiche floating point possono inizializzare scale candidate ma
   non sostituiscono il successivo replay intero esatto. Compilare una
   sola mappa comune ai tre contesti e verificare RNE, RMS, LUT e range
   nel replay; in caso di modifica delle scale invalidare le tracce
   dipendenti e ripetere la validazione. Non adattare Γ ai challenge o
   al transcript della prova. Il compilatore canonico possiede il DAG;
   il positivo composto inferenza/prova resta quello del piccolo `Profile`.
   Il nuovo [dispatcher canonico per righe](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_prepare.rs)
   copre embedding, matrici, RMS, RNE, affine, GELU, gate, RoPE, QK, EXP30,
   PV, softcap e argmax. Le righe RMS mantengono il reshape delle teste,
   `lm_head` la selezione originale; QK/PV chiedono solo KV causale e
   RoPE usa posizioni assolute. Le visite agli istogrammi sono restituite
   al caller senza costruire istogrammi o A completi. Il driver per token
   segue il DAG, esegue le 32 righe testa/query quando necessarie e demanda
   lo storage al consumer. Lo [storage CPU del trial](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_calibration.rs)
   ora collega W packed a una riga, A viva e KV causale, rilascia all'ultimo
   consumer e accumula min/max e istogrammi. Non materializza Snapshot/A
   completi; i test restano sottografi sintetici, senza validazione di un
   forward reale. Restano identità/input reali, esecuzione dell'inizializzatore,
   eventuale adattamento delle scale e replay certificato completo nei tre contesti.
   Un manifest da solo non rende il fixture un runner Gemma.
   Il padding query interno è fornito virtualmente: D matematico zero
   (word signed −32767), E=2^30, Z/Pi zero. Il lookup originale lo include,
   perciò l'istogramma aggiunge una sola volta `32*106*(O+150)` visite
   all'entry zero. Questa non è una nuova enumerazione o un nuovo circuito;
   i conteggi lookup canonici già comprendono quei rettangoli.
3. **Congelamento.** Fissare mappe, identità dei dati, regole, tabelle e
   digest dopo la validazione numerica; confrontare Python e Rust sulla
   stessa relazione intera, non pretendere uguaglianza con BF16.
   Ricompilare RMS/PCG e il ledger integrato dal Γ congelato. Un run di
   calibrazione non dimostra il tempo della prova, e il futuro benchmark
   della prova non dimostra da solo la qualità della calibrazione.

La calibrazione reale è quindi un prerequisito separato del preflight
H100 selezionato. L'[harness offline](../../scripts/c71_calibrate.py) ora
collega input da file, tabelle certificate e controller dei tre trial.
Il binario `c71_calibration describe` esporta i nomi/ID pinned; `recipes`
compila una candidata con 772 esponenti W e 1.435 A, e `check-input`
controlla forme, ricette comuni e riserve dei tre contesti senza leggere W.
La candidata JSON contiene solo `weight_exponents_by_tensor` e
`activation_exponents_by_source`; non dichiara da sé una calibrazione.

L'[inizializzatore A](../../scripts/c71_activation_pilot.py) consuma la
proiezione semantica esportata da `describe`: 1.436 step, inclusa argmax,
e tutti i 1.435 ID A. Non duplica il routing dei 60 layer o i dieci alias
K/V globali pre-norm. Riusa NumPy già installato, blocchi W da massimo
128 righe e le costanti RoPE Q30 esistenti; libera A all'ultimo consumer.
Esegue floating RMS/GELU/softmax su W dequantizzato, non il modello BF16
o EXP30 intero. Tutti i 450 token, incluso l'ultimo emesso di ogni risposta,
aggiornano KV causale; `lm_head` e decisioni operano solo sulle righe 99–148.
Una mappa comune usa l'esponente minimo RNE-fit degli estremi binary64
osservati più un bit di margine, salvo embedding legato a W e Pi a −14.
Il margine è un'euristica, non garantisce assenza di overflow nel replay:
se serve cambiare Γ, ripartire dal prefisso vuoto e ricontrollare tutti i trial.
Un errore impedisce il riuso dello stato parziale. Report e candidata non
si sovrascrivono; hash di ingest, packed, workload e binario accompagnano
il risultato, che resta `calibrated:false` anche quando compila.

Il modo `plan` non legge W: conta **26.782.043.904.000 B** di letture
logiche W e **13.390.420.377.600** prodotti scalari delle matrici nel pilot.
Non sono byte fisici disco/HBM o tempo CPU/H100: la cache del sistema e
il backend BLAS non sono modellati. Il blocco W i16+f64 occupa al massimo
27.525.120 B; il KV finale f64 ha payload 1.622.016.000 B. Questi non sono
picco fisico completo né memoria dell'arena della prova; A temporanea,
stack di KV per attention, allocator, NumPy/BLAS e cache OS restano separati.
La deadline del modo `run` copre il loop numerico, non l'hash preliminare
del packed né le invocazioni native limitate separatamente a 60 s.
Il [test](../../tests/test_c71_activation_pilot.py) verifica tutte le famiglie
di operatori in un grafo piccolo, RNE ai confini, causalità, ultimo token,
provenienza/errori e routing pubblico canonico. Non inizializza scale reali
e non autorizza l'esecuzione pesante sulla VM locale.
Il [record 19f53be](../../benchmarks/results/c71-activation-pilot-2026-09-26-19f53bed7022.json)
conserva questi controlli e quelli del wrapper intero, 13 test passati su
SHA pulita, senza credito di calibrazione o hardware.

Il wrapper congela la candidata in una copia temporanea, verifica il
report d'ingest e l'hash del packed e genera GELU/EXP30/softcap/Q30 usando
le funzioni certificate esistenti. Il codec delle tabelle è 24.414.870 B:
60 GELU i16, 60 EXP30 i32, softcap i16, poi RoPE local/global per tutte le
450 posizioni assolute, in little endian. Il binario Rust ne controlla
forma e identità, non ricalcola la certificazione numerica Python.
Un file arbitrario passato direttamente a Rust non riceve quel credito.

Il modo `ledger` del wrapper riusa quella candidata congelata e le stesse
tabelle, senza leggere W o attivazioni. Esporta le riserve Fp3 dei tre
contesti e la somma in righe base (tre per Fp3), esclusi installazione W
e bootstrap. Collega il census RMS preesistente a `Recipes::rms`; lo
screen Python ricompila gli stessi 421 tripletti e confronta programmi,
gate per livello e supporti originali. Non usa più scale zero quando il
record contiene ricette differenti. Conserva digest di candidata,
ricette/tabelle e binario; il controllo nonzero sintetico non promuove
`calibrated`, `complete_work`, picco fisico o readiness H100. Questo è il
raccordo da rieseguire sul futuro Γ congelato, non un nuovo ledger completo.
Il [record 79634a3](../../benchmarks/results/c71-candidate-ledger-2026-09-26-79634a3938a7.json)
conserva il controllo nonzero e le regressioni: 22 test passati su SHA
pulita, senza W reale o credito hardware.

Il controller parte da KV vuoto, usa lo stesso W/Γ per i tre contesti e
il prompt pinned a ogni tentativo; trasferisce il KV soltanto dopo
`finish`, senza clonare i buffer delle righe. Non accetta KV importato,
trial parziali, scale cambiate, riordino o un quarto tentativo. Il report
completo contiene token, range di tutte le sorgenti e contatori dei tre
trial solo dopo il loro successo; gli errori del replay e i timeout hanno
record separati di fallimento, senza sovrascrivere risultati esistenti.
Il [wrapper conserva stdout/stderr](evidence.md#calibration-failure-records) anche parziali dopo un errore o timeout,
distinguendo il codice del worker da quello del controllo. Un exit zero
con JSON invalido, duplicato, non-oggetto o trial non completo produce
un record di fallimento, non una conclusione positiva. Un report valido
resta comunque `calibrated:false` e `credit:false`.
Tabelle e report JSON ora condividono la pubblicazione temporanea con
fsync e link esclusivo: un errore non espone un report parziale e una
pubblicazione concorrente non sostituisce il file già presente.
Il limite del payload comprende KV precedente e cache di riga W, ma
esclude ancora tabelle/descrittori, workspace interni e allocator: non è
un limite del picco fisico completo. Il trasferimento finale conserva
405.504.000 B di KV per 450 token, costo offline già distinto dalla prova.

I controlli locali esercitano il formato completo delle tabelle pubbliche
su scale sintetiche e il trasferimento KV con righe sintetiche; il secondo
test costruisce esplicitamente lo stato finale per controllare il solo
handoff, senza attribuirgli un forward numerico. Non si propone ancora
una spesa: mancano l'inizializzazione delle scale A sui pesi reali, il
replay completo positivo e il relativo piano di esecuzione autorizzato.
`calibrated:false` resta esplicito anche per un trial intero positivo:
freeze, confronto della relazione e trasferimento al ledger sono successivi.
Il [record su SHA pulita 5e9d8ff](../../benchmarks/results/c71-calibration-fixed-run-inputs-2026-09-26-5e9d8ff3e827.json)
conserva questi controlli e le regressioni del registro e della proof
ridotta; non sostituisce l'evidenza del trial reale ancora mancante.

Il test `c71_b12_native_canonical_numeric_rows_original_routes` usa le
geometrie originali a O=0/150/300 e dati/tabelle sintetici dichiarati,
inclusa una scala RMS nonzero per intercettare il riuso del vecchio `[0;3]`.
Controlla proiezione/RNE, reshape RMS, RoPE/RNE, GELU/gate, QK/EXP30/PV,
softcap/argmax e rifiuti di indirizzi, padding, pesi e marker invalidi.
Il probe `lm_head` si arresta dopo il primo indirizzo selezionato, prima
di eseguire la grande proiezione. Il driver è eseguito sul solo suffisso
softcap/argmax, con controllo delle righe 98/99/148/149, consumer successivo
al producer, conteggio delle visite all'istogramma e mancato aggiornamento
del token dopo errore del sink. I layer precedenti non sono eseguiti in
questo fixture. È un controllo CPU per righe, senza
proof o campo GKR, non calibrazione reale o inferenza completa.
Il test verifica anche le costanti di padding e la somma delle visite
vive/pubbliche contro il rettangolo originale `32*256*(O+150)`.
Il [record d3690a6](../../benchmarks/results/c71-canonical-calibration-rows-2026-09-26-d3690a6d0abd.json)
conserva il test e la regressione separata della proof ridotta originale,
entrambi passati da SHA pulita entro i limiti locali.
Il ledger hardware conserva i costi producer ancora aperti: non si
sostituiscono i suoi costi con il tempo CPU di questo test né si attribuisce
credito al picco fisico. Il dispatcher non modifica la schedule GPU
selezionata o il suo margine pianificato.

Lo storage offline distingue letture W, A corrente, KV precedente e KV
corrente, righe emesse e visite istogramma. Il payload KV corrente completo
è 135.168.000 B, gli istogrammi completi 31.718.940 B; il KV precedente
fornito esternamente vale 0 / 135.168.000 / 270.336.000 B. Sono costi del
trial numerico, non nuove allocazioni da sommare al ledger GPU: il KV totale
è già presente nel budget globale della risposta. Il picco del trial conta
payload retained e bundle entrante conservativamente; non comprende tutti
i temporanei interni dei producer o l'allocator e non chiude il picco fisico.

Il test `c71_b12_native_canonical_calibration_storage_release_and_ranges`
esegue embedding → affine → RNE da due righe packed, GELU → gate e PV con
KV corrente/precedente a O=0/150/300. Controlla codec simmetrico, cache W,
input troncato, letture future/rilasciate, budget del payload e arresto dopo
errore. Le statistiche dei sottografi non vengono dichiarate Γ calibrato;
`finish` richiede 150 token e copertura completa prima di accettare un trial.
Nessun tempo CPU viene trasferito al ledger H100.
Il [record c862023](../../benchmarks/results/c71-canonical-calibration-storage-2026-09-26-c862023d0c8b.json)
conserva i tre trace del test dello storage e la regressione del dispatcher,
entrambi passati da SHA pulita; distingue ordine degli ID e ordine packed.
