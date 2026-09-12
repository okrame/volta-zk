# C7.1 — Screen di nuove famiglie

2026-09-12 · [Contratto](design.md#owner-authorized-pcsstate-experiment) ·
[Screen precedente](pcs-state-screen.md#screen-minimo-sotto-i-tetti-assoluti).

**Esito: nessuna costruzione completa selezionabile, `credit:false`.**
La ricerca comprende bootstrap silent/streaming, chosen-input VOLE,
PCS con codici, sumcheck a memoria ridotta, lookup frazionari e PCS
hiding su reticoli o gruppi bilineari. Le esclusioni sotto riguardano le sostituzioni specificate;
non sono un'impossibilità per tutte le combinazioni di queste famiglie.
Non si implementa né si ottimizza una linea già respinta.

**Priorità di contributo, non selezione: consumer Shout con endpoint DV
originali e witness entro arena.** Il [confronto mirato](#confronto-mirato-akita-shout-e-logup-dory)
trova ulteriori ostacoli al port letterale di entrambe le PCS; il vantaggio
di Dory sulle valutazioni nascoste non basta a preferire l'intera
composizione LogUp–Dory. Nessuna delle due ha un tempo completo finito
giustificato sotto 50 s. Non si avvia un'implementazione.

Capacità richiesta/esaminata: **C=3, 100+50 token per risposta,
O=0/150/300, 450 token complessivi**. Capacità acquisita sotto l'intero
contratto: **nessuna**. Per ogni contesto valgono 35/40/40 milioni di byte,
inclusi installazione, bootstrap per sessione e ogni dato necessario al
verifier; niente ammortamento sui turni successivi. Gli ignoti sotto
hanno upper di ammissione infinito, non costo zero.

## Screen prima di un eventuale port

| Sostituzione esaminata | Certificato completo | Memoria globale / dinamica; traffico e passaggi | Lavoro e tempo completo; disposizione |
|---|---|---|---|
| Dory **PCG** silent al posto del bootstrap, consumer/PCS B12 o RNE v2 invariati | Il nuovo bootstrap non è censito a Goldilocks/Fp3 e sicurezza C7.1; il corpo B12 supera già i cap. RNE v2 riduce il corpo, non il costo sotto | Chiavi/rumore VOLE sono di sessione. Restano gli alberi P/S: 421 TB per il gruppo D34, 567/592/592 TB di sole scritture per risposta; 8 passaggi di costruzione più fold GKR | Restano circa 200,59/209,31/209,31 mila miliardi di prodotti Fp3 del core e >169/176/176 s di sole scritture al picco HBM. **Respinta per memoria/tempo**, senza approfondire il PCG |
| LogVOLE chosen-input al posto di `Authenticate`, stessa schedule seriale P/S RNE v2 | Ai parametri pubblicati, soli digest >=351.436.800/459.571.200/459.571.200 byte; setup, residui e PCS aggiuntivi | Un digest per round dipendente da FS; 1.560/2.040/2.040 invocazioni shrink/expand. Nessuna tabella dipendente da Delta diventa globale. Gli alberi invariati restano fuori memoria | **Respinta** già per digest e consumer. Non si attribuisce il throughput di un unico grande batch a migliaia di query piccole |
| LiftWHIR/Brakedown al posto della PCS, layout flat denso e consumer invariati | Manca il codec composto; né una PCS corta né il batching Jagged rimuovono bootstrap e P/S | Una sola A/D34 in elementi base occupa 137.438.953.472 byte, prima di codifica, maschere, W e temporanei. W non mascherato può essere globale, A no; commit/encode, apertura e hash sono passaggi distinti | **Respinta la materializzazione densa**, già per memoria e per i consumer invariati. Le velocità pubblicate su domini/campi diversi non danno un tempo H100 |
| Scribe, sostituendo il prover con read-write streaming su disco | Certificato canonico e adattamento DV non definiti | Sposta gli intermedi della prova in memoria esterna dinamica; non è materiale globale W. Almeno scrittura e rilettura degli intermedi, oltre a commit e fold | **Respinta per memoria autorizzata**, prima di stimare il tempo. Il basso RSS pubblicato non include il requisito di assenza di spill |
| Akita + lookup Shout + sumcheck in sola lettura, in sostituzione anche dei consumer | Nessun conteggio completo: setup, ZK, collegamento ai MAC e prova dei produttori mancano. 61–70 KB è la PCS pubblicata, non Gemma | Potenziale riuso di setup pubblico e hint di W; byte globali, workspace dinamico, visite W/A e traffico canonici non istanziati. Il backend denso base64 di A richiederebbe già 137 GB | **Non selezionabile allo screen**: ZK di Akita è lavoro futuro; costi della composizione privata e tempo H100 ignoti. Si ferma qui la verifica minima, senza progettare un wrapper ZK o trasferire bound B12 |

Per i numeri ereditati della prima riga vale il
[conteggio dei consumer](pcs-state-screen.md#memoria-passaggi-traffico-e-tempo),
che resta applicabile perché questi non cambiano. Se si cambia anche il
prover P/S, quel lower di scrittura cessa di essere applicabile: occorre
contare il nuovo algoritmo, non dichiarare gratis la sua ricomputazione.

## Costi decisivi chiariti

**LogVOLE: distinguere correlazioni casuali da valori scelti dopo FS.**
Il [paper, §§12.1–12.2](../../sota/2026-0925-logvole.md) usa
`n=8192`, `log2(q)=220`: un digest ring occupa nominalmente
`n*220/8=225280` byte. In
[`prove_tree_with_first_weight`](../../rust/volta-pcs/src/c71_matrix/range.rs)
si autenticano i quattro coefficienti, si assorbe il messaggio e solo
allora si deriva la sfida che determina i coefficienti successivi.
Una sostituzione locale con chosen-input VOLE richiede perciò almeno
un digest per round, anche raggruppando tutti i coefficienti di quel round.
Un gruppo Dd ha `sum(d+l for l in range(8))=8*d+28` round;
i gruppi canonici danno i lower in tabella. Il conto esclude persino
gli split fra livelli e assume una sola query anche per Fp3.

La versione non interattiva elimina la risposta con la root key, non il
digest inviato dal prover. I circa 38 MB di setup pubblicati sono traffico
di setup, prevalentemente **verifier → prover**: non si usano come lower
dei byte ricevuti dal verifier. Si contano comunque nel lavoro/trasporto.
I benchmark sono a campo di 55 bit e sicurezza statistica 40 bit; il
protocollo semi-onesto misurato usa ottimizzazioni non conservate dalla
variante malevola. Non sono un profilo equivalente a C7.1.
Usare invece una sola query per generare correlazioni casuali in anticipo
evita il lower per round, ma conserva correzioni online, consumer e PCS:
ricade nel primo tipo di sostituzione, non risolve la selezione.

**Akita: pista strutturalmente interessante, non candidata ammessa.**
Il [paper appena acquisito, §§13–14](../../sota/2026-09-12-akita.md)
conferma workspace sublineare oltre al polinomio e impegni adatti a dati
sparsi. Per questo, insieme ai lookup
[Shout](https://eprint.iacr.org/2025/105), è interessante
per evitare sia i codeword RS sia i 256 nodi foglia
P/S per byte. È una priorità concettuale, **non uno screen superato**.
La §14 lascia esplicitamente ZK al lavoro futuro. La §13.1 misura aperture
pubbliche, distingue coefficienti da bit impegnati ed esclude planning
dal tempo online; i profili di apertura sono estensioni di grado 4/2/1
su campi base 32/64/128 bit, non il nostro Fp3. La §13.4 esclude inoltre
tracing, preprocessing e setup dai tempi Jolt. Servirebbero un'apertura
privata negli originali VOLE-MAC, same-W/KV e contabilità della nuova
semantica di campo; non basta sostituire la libreria PCS.

**Sumcheck a memoria ridotta non fornisce gratis il witness.**
[Time-Space Trade-Offs for Sumcheck](../../sota/2025-1473-time-space-tradeoffs-sumcheck.md)
distingue una singola multilineare dai prodotti di multilineari. La
procedura a due passaggi per la prima non si trasferisce al GKR cubico.
L'accesso in sola lettura ai polinomi è una premessa: su A gli stream
devono essere conservati nei limiti ordinari o rigenerati. Preparazione,
replay del forward, costruzione dei prodotti e PCS rimangono nel costo.
Il modello Scribe, invece, concede proprio lo stato esterno qui vietato.

## Estensione: lookup frazionari e PCS hiding

**Nessuna nuova candidata completa supera lo screen.** **LogUp-GKR + PCS Dory
con valutazione impegnata** cambia anche il consumer e dispone già di
un endpoint nascosto, a differenza della PCS pubblica Akita. Non viene
selezionata: mancano il ponte al campo/MAC corrente e uno schedule del
witness entro l'arena. Il vantaggio strutturale non è una previsione <=50 s.
Qui Dory indica la **PCS del 2020**, non il PCG silent omonimo del 2025.

Lo screen seguente precede qualsiasi port. Conserva C=3, stesso Gemma,
semantica intera, originali e obblighi W/KV; non usa una PCS per operatore.
Per ciascuna riga il certificato completo P1/P2/P3 e il tempo completo
restano **ignoti**, dunque senza upper finito di ammissione. Le dimensioni
di una singola PCS pubblicata non sostituiscono quei tre conteggi.

| Linea e costo decisivo | Memoria globale / dinamica | Passaggi, traffico, crittografia e disposizione |
|---|---|---|
| LogUp-GKR al posto dei P/S RNE, poi PCS privata | Tabelle pubbliche riusabili; molteplicità e intermedi dipendono da A e dalle sfide. Il solo albero interno esplicito D34 costa **824.633.720.784 byte** con due Fp3 per nodo, senza foglie né fold | 34 livelli di costruzione; almeno una scrittura e successive letture degli intermedi, poi i sumcheck. La §3.3 stima circa `43N` prodotti e `29N` somme di campo per il solo GKR frazionario, con intermedi disponibili. **Respinta la materializzazione**; non si trasferiscono i 169 s della diversa costruzione a 256 foglie |
| Jindo hiding, con consumer da sostituire | Setup pubblico/trasformazioni di W possono essere globali; `op` conserva matrici codificate, maschere e randomness. Una A/D34 densa anche a soli 8 byte/cella costa **137.438.953.472 byte**, prima del resto | Split/encode, commitment e apertura sono fasi distinte; il backend denso richiede almeno scrittura/lettura delle matrici, oltre a prodotti ring/NTT e sampling. **Respinto il layout denso**. Streaming non istanziato; inoltre la PCS pubblica y e il suo slot encoding non offre Fp3 nativo |
| Dory PCS hiding, con LogUp e accesso al witness da sostituire | Hint privati delle righe di W possono evitare nuove MSM sui pesi; quelli di A sono dinamici. La rappresentazione densa a scalari di 32 byte costa **549.755.813.888 byte** per A/D34 | Commit A: MSM su N coefficienti; apertura: contrazione del witness più operazioni di gruppo/pairing su vettori ridotti. Commit e contrazione visitano A separatamente. **Respinto quel backend denso**; un reader packed richiede costi propri, così come il ponte Goldilocks/Fp3 ↔ campo scalare |

Questi sono lower delle rappresentazioni specificate, non della memoria
minima delle famiglie. Tutte eccedono già gli 80 GB totali, prima di W da
61,39 GB e arena da 6,44 GB. Non serve attribuire loro una banda effettiva
per respingerle; spostare A o `op` su host/disco violerebbe lo stesso contratto.
Per varianti senza quelle allocazioni restano da contare witness/replay,
bootstrap fresco, producer, range, PCS, serializzazione e IO: nessuna voce
mancante viene sostituita da zero o da un tempo CPU riscalato alla H100.

**Il nuovo sumcheck streaming chiarisce il costo della ricomputazione.**
[Dao et al., Fig. 2 e §C.4](../../sota/2026-0587-speeding-up-sumcheck.md)
richiedono stream enumerabili in spazio piccolo. Per il prodotto cubico,
`k=2`, D34/D35, la schedule dà finestre **1,2,4,8,8**, poi un passaggio
finale: **sei visite complete degli input**, non due. Il workspace del
sumcheck è sublineare; non include la produzione dei suoi input. Applicata
a un albero LogUp, la premessa riguarda i valori dei figli di ciascun
livello, da conservare o rigenerare dopo le sfide. I `43N/29N` sopra non
includono questa nuova rigenerazione. Se le sei visite leggessero W packed
dall'esterno, sarebbero 368.368.143.360 byte, **7,37 s a 50 GB/s**; con
15 s riservati alla crittografia rimarrebbero 27,63 s per inferenza e
tutto il resto. È solo sensibilità sequenziale, con la banda motivata sotto,
non uno schedule completo: ulteriori stream, copie e replay si sommano.
Se fossero sei letture dirette di W per la prova, supererebbero anche le
quattro ammesse dal riferimento. Il paper migliora i prodotti generici,
ma non dimostra lavoro totale non crescente sui prefissi C7.1.

**Jindo: hiding e campo non sono già il ponte richiesto.**
La [Def. 10](../../sota/2026-0044-jindo.md) simula dati la valutazione
pubblica `y=f(x)`; non attesta direttamente il MAC privato originale.
Nel suo encoding (§4.1), `d` è potenza di due, `γ,δ` suoi divisori:
il grado dello slot field `d/δ` non può essere 3. Inoltre per Goldilocks
`p-1` ha valutazione 3-adica uno; `p=b^(d/γ)+1` forza `d/γ=1`, quindi
`b=p-1`, anziché il radix di circa 32 bit dei benchmark. Questo esclude
il port letterale e il trasferimento dei suoi costi, non altri encoding.
I parametri pubblicati usano stime MSIS/MLWE e spreadness euristica;
non forniscono i vantaggi concreti B12 a T121/M93. La verifica minima
si ferma qui, senza progettare un wrapper o estrapolare il benchmark D20.

**Dory: endpoint impegnato, ma in un altro campo.**
Le [§§5–6](../../sota/2020-1274-dory-pcs.md) provano una valutazione
impegnata e nascondono la matrice. L'operazione `v=LᵀM` resta una scansione
scalare: il costo sublineare di gruppo dell'apertura non la elimina.
Le sue identità vivono nel campo scalare del gruppo, non in Goldilocks/Fp3;
inviare le tre coordinate come scalari non preserva automaticamente le
riduzioni modulo p né `k=m+Delta*x`. Mancano costo e sicurezza del ponte,
FS malevolo e composizione same-W/KV: SXDH/HVSZK non ereditano B12.
Solo hint deterministici privati di W, senza nuove emissioni, hanno il
riuso funzionale già autorizzato. Pubblicare o riusare commitment/blinding
fra sessioni richiede una prova della vista congiunta; maschere delle prove
e VOLE restano freschi. Nessun hint di A diventa globale.

## Confronto mirato Akita-Shout e LogUp-Dory

Screen del 2026-09-12, prima di progettare nuovi wrapper; **`credit:false`**.
Capacità esaminata sempre C=3 canonica, capacità soddisfatta **nessuna**.
I costi seguenti chiariscono ostacoli decisivi, non completano i costi
mancanti delle composizioni private. Per entrambe P1/P2/P3 e tempo completo
hanno ancora upper di ammissione infinito; i lower non sono previsioni.

**Shout è un possibile sostituto del consumer, non soltanto della PCS.**
Il [paper, §§4.1 e 6](../../sota/2025-0105-twist-shout.md) controlla lettura,
booleanità, peso uno e indirizzo. Per K=256, d=1, il core usa T+3K prodotti;
il conto generale §6.4 dà il termine conservativo 6T più termini di tabella
per il PIOP combinato. LogUp §3.3 dà circa 43T prodotti e 29T somme.
Applicando **solo quei modelli aritmetici** alle 23.135.780.864 /
24.142.413.824 / 24.142.413.824 celle virtuali RNE censite:

| Voce parziale | O=0 | O=150/300 |
|---|---:|---:|
| Shout, termine 6T, prodotti di campo | 138.814.685.184 | 144.854.482.944 |
| LogUp, termine 43T, prodotti di campo | 994.838.577.152 | 1.038.123.794.432 |
| Throughput del solo termine Shout per stare in 15 s | 9,25 miliardi/s | 9,66 miliardi/s |
| Throughput del solo termine LogUp per stare in 15 s | 66,32 miliardi/s | 69,21 miliardi/s |

Non sono lower universali né costi del nostro adattamento: Shout qui assume
una tabella pubblica e sfide/pesi della propria schedule. Le tabelle RNE
variano per ricetta/lane e sono combinate **dopo FS** da
[`function_tables(recipe,beta)`](../../rust/volta-pcs/src/c71_matrix/rne.rs).
Pesi L e MAC originali non sono automaticamente i claim Shout del paper.
Il batch deve provare anche questa corrispondenza, senza un passaggio qN.
Le 892×8 tabelle combinate da 256 Fp3 costerebbero 43.843.584 byte se
conservate tutte: sono temporanei di risposta, non materiale globale.
Le ricette non combinate sono riusabili. Il 6T non comprende PCS, adapter,
ZK, bootstrap, produttori, replay o IO; nessun throughput H100 per essi
è verificato. I 15 s sono una soglia di screen da condividere con le altre
operazioni crittografiche, non una disponibilità acquisita.

| Implementazione sottoposta allo screen | Memoria, passaggi e traffico | Disposizione |
|---|---|---|
| Shout §6, array espliciti su un gruppo D34, campo Fp3 | E/D ha T elementi; §6.3 costruisce anche H di T elementi dopo gli 8 round indirizzo. D+H = **824.633.720.832 byte**, prima degli indirizzi e della PCS. Seguono 34 round ciclo con letture/fold. Una sola scrittura e lettura di **un** array sui gruppi O=0 costa 1.110.517.481.472 byte | **Respinto per memoria**, anche senza la seconda copia; non si approfondisce il kernel denso |
| Akita–Shout con pad Fp3 indipendente su ogni cella one-hot | La matrice logica ha 256×2^34 celle: una copia mascherata costa **105.553.116.266.496 byte**. Una scrittura e lettura richiedono già **63,02 s al picco HBM** di 3,35 TB/s, senza commitment | **Respinta questa privatizzazione densa** per memoria e tempo. Maschere strutturate potrebbero cambiare il conto, ma la loro privacy va dimostrata |
| Shout con input virtuali, array rigenerati e PCS privata | Solo setup pubblico/hint deterministici W sono globali; byte del setup espanso e workspace PCS non istanziati. Gli indirizzi dipendono da A. Numero completo di replay, passaggi, traffico e costo crypto ignoti | **Non selezionabile**; spazio sublineare oltre all'input non fornisce quell'input entro arena |
| LogUp–Dory con reader packed | Può evitare l'array di scalari da 549,76 GB, ma richiede ancora commitment su N coefficienti, contrazione LᵀM, produzione/rigenerazione degli alberi e ponte di campo. Hint A sono dinamici; hint W e setup vanno dimensionati | **Non selezionabile**, senza upper completo di memoria/tempo; i backend densi restano respinti |

Per la riga virtuale non si presume un passaggio unico né overlap: usare
50 GB/s esterni e 2,68 TB/s HBM è solo la sensibilità motivata sotto.
Il tetto di 35 s di IO esterno, riservandone 15 al resto, resta 1,75 TB;
non autorizza spill di A. Setup globale, caricamento e tutte le letture
si registrano, oltre al setup fresco per sessione. La mancata misura
della banda effettiva e del resto impedisce una previsione completa.

**Akita richiede più della ZK.** La §3.1 usa d potenza di due e un embedding
di F_(q^k) con k divisore di d/s_split. Quella via non ammette k=3:
**Fp3 non entra nel packing pubblicato**, anche scegliendo q=Goldilocks.
Trattare tre coordinate non è l'embedding moltiplicativo richiesto.
Una riduzione fra coordinate della stessa caratteristica, o un altro ring,
è lavoro crittografico nuovo da contare e provare; non un cambio di codec.
Inoltre il Cor. 10.32 limita il bound FS a
`log2(|E|) - log2(c) - log2(Q+1)` se il ledger contiene c/|E|.
Con i campi di apertura da circa 128 bit dei benchmark e Q=2^64, già
c=1 lascia **meno di 64 bit**, sotto i 78 richiesti, prima degli altri
errori. Per quell'analisi servono più di 142+log2(c) bit di campo;
restringere Q sarebbe indebolire il confronto. Anche con un nuovo campo
vanno ricontati tutti i termini ring/FS e le ipotesi MSIS alle risorse
della riduzione. Questo è un limite del bound pubblicato, non un attacco
dimostrato. I 61–70 KB e i tempi pubblicati non sono parametri C7.1.

**Dory: il ponte non si limita a certificare tre scalari finali.** Se il
gruppo ha ordine primo r diverso da p, non esiste embedding unitale di
Fp in Fr: p·1=0 nel primo campo e p·1≠0 nel secondo. La contrazione
multilineare Dory è in Fr; un attestato sul solo valore finale non prova
che sia la valutazione Fp3 della stessa A. Vanno collegati commitment,
coefficienti/pesi, riduzioni modulari e **MAC originale**. Spostare tutto
GKR/MAC in Fr evita quel ponte ma cambia campo, bootstrap e riduzioni:
è un'altra costruzione da sottoporre al contratto, senza credito B12.
Non segue che occorra emulare ogni gate in aritmetica non nativa: eventuali
lift interi o riduzioni dei pesi a basso rango richiedono conti e prove
propri. Qui non si attribuisce loro un lower di lavoro per cella.

**Contributi candidati, in ordine di dipendenza.** La prima verifica da
riaprire riguarda un consumer di funzioni byte **Shout con endpoint DV**:
indirizzo legato ai byte della stessa A, lettura legata ai P/S originali,
booleanità/peso uno, tabelle/lane corrette e padding. La componente nuova
utile sarebbe la composizione privata con witness virtuale e un numero
finito di passaggi entro arena, non Shout stesso. Finché manca quel conto
non si progetta una PCS privata completa. Successivamente servirebbero
un'apertura nascosta compatibile col campo/MAC e il bootstrap fresco
compatto: nessuna PCS rende gratuito il COPE corrente. Con 13.824 byte
di sole correzioni per riga Fp3, i cap ospitano al massimo 2.531/2.893
righe **prima di ogni altro byte**.

Il contributo sul materiale globale consiste nel separare hint privati
deterministici di W da ogni emissione mascherata, e provare same-W e ZK
sulla vista congiunta delle sessioni sotto un budget avversariale globale.
La capacità C=3 è per conversazione; non dimostra da sola il riuso fra
conversazioni. Maschere/VOLE restano freschi, i costi di rigenerarli restano
nel turno. I lemmi `Mac.Valid` e l'induzione KV di security §6 possono
essere riusati soltanto dopo averne scaricato le nuove premesse. Non c'è
una rivendicazione di novità accademica o un nuovo teorema dimostrato.

**Famiglia aggiuntiva controllata: BlindFold.** La
[documentazione primaria Jolt](https://jolt.a16zcrypto.com/how/blindfold.html)
nasconde i messaggi sumcheck e prova le relazioni del verifier in un
piccolo R1CS, collegato alle valutazioni impegnate Dory. È un modello
utile di separazione fra grande witness e piccolo transcript; non
privatizza la PCS Akita pubblica né fornisce un ponte Fp3–MAC o uno schedule
del grande witness. Non si procede al port: costi completi ancora ignoti.
[Jolt Atlas](https://arxiv.org/html/2602.17452v1), §§1.2 e 4, usa invece
HyperKZG e ammette trasformazioni del modello; non è un confronto acquisito
a setup/semantica invariati. Non si importano i suoi benchmark.

## IO, sicurezza e criterio di riapertura

Per ogni nuova linea il tempo da chiudere è una **somma senza overlap
presunto**: inferenza + witness/replay + PCG/setup di sessione + crypto +
serializzazione + IO residuo. Per quest'ultimo contare separatamente
HBM, copie e accessi esterni, senza contare due volte quelli già inclusi
nei kernel. Il caricamento globale si registra una volta e resta nel
lavoro totale. Non c'è una banda effettiva misurata per queste composizioni.

Come sensibilità, [lo screen hardware](pcs-state-screen.md#memoria-passaggi-traffico-e-tempo)
usa 50 GB/s esterni e 2,68 TB/s HBM (rispettivamente 78,125% e 80% dei
picchi citati), solo per accessi sequenziali favorevoli. Riservando 15 s
al resto, 35 s di IO esterno consentono **1,75 TB** complessivi: una
lettura del vecchio W codificato da 2.199.023.255.552 byte costa 43,98 s,
due 87,96 s. I 15 s sono una riserva di screen, non una misura crypto;
per le nuove composizioni manca ancora un upper del resto entro tale
riserva. Accessi sparsi, hash, scritture e copie non sono assorbiti dal
picco PCIe. La concessione globale risolve la capienza, non questa somma.

Materiale riusabile: funzioni deterministiche private di W/Γ e setup
pubblico indipendente da sessione; va dimostrata la sicurezza della vista
di tutte le sessioni che li usano. Hint privati senza nuove emissioni non
autorizzano riuso di correlazioni, pad o maschere. Dory PCG aggiunge
ipotesi LPN e un'istanza di campo da valutare; LogVOLE e Akita introducono
ipotesi su reticoli e riduzioni proprie. Non sono già le ipotesi B12.
Le identità `Mac.Valid` restano riusabili nei segni/campi dichiarati;
né esse né `OpeningMac` forniscono ZK/binding della nuova PCS. Per ora
non cambia [security](security.md), che prova esclusivamente B12.

Non è dimostrato lavoro totale non crescente per alcuna nuova linea,
su nessuno dei prefissi 1/2/3: anche preparazione globale, bootstrap e
replay vanno confrontati con la stessa baseline. La sua infeasibilità
densa non concede credito automatico. Per riaprire serve una composizione
con endpoint privati e un conteggio finito di **tutti** questi costi;
non basta un benchmark PCS, un nuovo PCG o tre certificati ridotti.

## Riproduzione locale e fonti

Il seguente controllo aritmetico usa il censimento canonico già verificato
dei gruppi RNE e non alloca witness. Eseguito il 2026-09-12; nessun run GPU,
benchmark, nuovo teorema o test di protocollo è attribuito allo screen.

```python
cells = (23_135_780_864, 24_142_413_824, 24_142_413_824)
rounds = [sum(8*d + 28 for d in range(35) if n >> d & 1) for n in cells]
digest = 8192 * 220 // 8
wire = [r * digest for r in rounds]
assert rounds == [1560, 2040, 2040]
assert wire == [351_436_800, 459_571_200, 459_571_200]
assert all(b > cap for b, cap in zip(wire, (35_000_000, 40_000_000, 40_000_000)))
assert 8 * 2**34 == 137_438_953_472 > 80_000_000_000
assert 35 * 50_000_000_000 == 1_750_000_000_000 < 2_199_023_255_552

# Nuove famiglie: lower dei layout espliciti, non memoria minima universale.
assert 48 * (2**34 - 1) == 824_633_720_784 > 80_000_000_000
assert 32 * 2**34 == 549_755_813_888 > 80_000_000_000
p = 2**64 - 2**32 + 1
assert (p - 1) % 3 == 0 and (p - 1) % 9 != 0
assert all(2**i != 3 for i in range(36))  # gradi slot Jindo ammessi
for ell in (34, 35):
    # Fig. 2, d=3: delta=2, alpha=2, k=2, cutoff ell/2.
    consumed, window, windows = 0, 1, []
    while 2 * (ell - consumed) > ell:
        window = min(window, ell // 4, ell - consumed)
        windows.append(window)
        consumed += window
        window *= 2
    assert windows == [1, 2, 4, 8, 8] and len(windows) + 1 == 6
assert 6 * 61_394_690_560 == 368_368_143_360

# Confronto mirato: aritmetica parziale, nessun tempo completo acquisito.
assert [6*n for n in cells] == [138_814_685_184, 144_854_482_944, 144_854_482_944]
assert [43*n for n in cells] == [994_838_577_152, 1_038_123_794_432, 1_038_123_794_432]
assert 48*2**34 == 824_633_720_832 > 6_442_450_944
assert 48*cells[0] == 1_110_517_481_472
assert 24*256*2**34 == 105_553_116_266_496
assert 48*256*2**34 > 50*3_350_000_000_000  # write+read >50 s persino al picco
assert 892*8*256*24 == 43_843_584  # tabelle combinate, dinamiche
assert all((2**i) % 3 for i in range(36))  # k=3 non divide d/s_split Akita
assert (2**64 + 1)*2**78 > 2**128  # anche c=1 non ammette il target FS
assert [cap//13_824 for cap in (35_000_000, 40_000_000)] == [2531, 2893]
```

Fonti lette nei Markdown conservati: [Dory PCG](../../sota/2025-1660-dory-streaming-vole.md),
[LogVOLE](../../sota/2026-0925-logvole.md), [LiftWHIR](../../sota/2026-1561-liftwhir.md),
[Brakedown](../../sota/2021-1043-brakedown.md), [Jagged](../../sota/2025-917-jagged-pcs.md),
[Scribe](../../sota/2024-1970-scribe.md), sumcheck e Akita sopra.
Metadati verificati sulle pagine primarie; il confronto mirato legge anche
Shout §§4/6, senza attribuirgli un port o un costo completo C7.1.
Il nuovo [PDF Akita](../../sota/2026-09-12-akita.pdf) proviene da
`https://assets.layerzero.network/pdf/akita.pdf`, scaricato il 2026-09-12
e convertito localmente con AnyDoc 0.1.7. SHA-256 PDF:
`b82969386ed3f006cf86ba95eb0ab02cd9f741ae79c98611680531b81a34f67d`;
Markdown: `566fe8c55c55bf331eb243872d66dbdbacb2df33b7642118c65e15ad44e608c6`.

Fonti aggiuntive degli screen, acquisite il 2026-09-12 e convertite con
AnyDoc 0.1.7; nessuna fonte precedente sovrascritta. Metadati primari:
[sumcheck](https://eprint.iacr.org/2026/587),
[Jindo](https://eprint.iacr.org/2026/044),
[Dory PCS](https://eprint.iacr.org/2020/1274).

| PDF conservato / URL di acquisizione | SHA-256 PDF / Markdown omonimo |
|---|---|
| [Sumcheck](../../sota/2026-0587-speeding-up-sumcheck.pdf), `https://cs.nyu.edu/~zd2131/papers/26-587.pdf` | `04ac867dc2d2e68f967bbb4550c1afe1340439e8b0aae1611464c4e433f8a1a7` / `630c077243d532bebfeb7b20cdc28280da40990439c6adcd101e23e2889d4f20` |
| [Jindo](../../sota/2026-0044-jindo.pdf), `https://eprint.iacr.org/2026/044.pdf` | `ebf0f9634b2d6a5c42e8f4810a7b9da07c3edd760cfca3d5a8159838d2bdc70e` / `c75c0bf0539a42ad4887c6cb1df54e635bfa09367910901b6a53d59224f45bc4` |
| [Dory PCS](../../sota/2020-1274-dory-pcs.pdf), `https://eprint.iacr.org/2020/1274.pdf` | `d0789bc9497d5532b53065176ed3c85d5d3360b23d20fd7e839174ec23518a52` / `b78c7f401ee77c6fadaa991a9287a815f0a6da960d3e115055db718e116d42a6` |
| [Twist and Shout](../../sota/2025-0105-twist-shout.pdf), `https://eprint.iacr.org/2025/105.pdf` | `0808fe28ffc921cd99df3c4a9f8afd0300c3e933bed2bfb2241f859982d4b538` / `1205252b260a2d6058fad79976067e7bc900c6c8430abf282247633bed9f1c44` |
