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
giustificato sotto 50 s. Il [nuovo screen residuo](#shout-con-endpoint-originali-screen-dei-costi-residui)
respinge anche la sostituzione dei soli P/S, indipendentemente dal costo Shout.
Il [bootstrap fresco](#bootstrap-fresco-dory-alimentato-da-b11) precede
ogni ulteriore approfondimento Shout. Non si avvia un'implementazione.

Capacità richiesta/esaminata: **C=3, 100+50 token per risposta,
O=0/150/300, 450 token complessivi**. Capacità acquisita sotto l'intero
contratto: **nessuna**. Per ogni contesto valgono 130/40/40 milioni di byte,
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

**Contributo candidato: consumer di funzioni byte Shout con endpoint DV.**
Deve legare indirizzo ai byte della stessa A, lettura ai P/S originali,
booleanità/peso uno, tabelle/lane corrette e padding. Il
[nuovo screen residuo](#shout-con-endpoint-originali-screen-dei-costi-residui)
chiarisce perché, prima di approfondirlo, va risolto anche il bootstrap.
Con 13.824 byte di sole correzioni per riga Fp3, i cap ospitano al massimo
5.063/2.893 righe **prima di ogni altro byte**.

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

## Shout con endpoint originali: screen dei costi residui

**Ultima deroga 130/40/40 MB, C=3 canonica; `credit:false`.** La candidata
più promettente come contributo resta Shout con witness virtuale e MAC
originali, per il minor lavoro aritmetico del consumer censito sopra.
Lo screen minimo distingue però la **sostituzione dei soli P/S RNE** da
una nuova composizione che cambi anche bootstrap, range e PCS. La prima
è respinta prima di approfondire il prover Shout, persino senza addebitarle
il suo costo ancora ignoto. Non si seleziona la seconda per implementazione.

Il [conteggio eseguibile](../../scripts/c71_pcs_state_screen.py), voce
`shout_residual_screen`, verificata dal [test locale](../../tests/test_c71_pcs_state_screen.py),
sottrae da
[`rne::required`](../../rust/volta-pcs/src/c71_matrix/rne.rs) solo il consumer
P/S. Restano `8*c + funzioni + prodotti + 1` correlazioni Fp3: otto per
round grado sette e una maschera finale. Per **ogni** shift ammesso il
lower è `8*c+1`. Il range W autentica separatamente tutti i 65.535 contatori
in [`range::prove`](../../rust/volta-pcs/src/c71_matrix/range.rs).

| Costo attribuibile alla risposta, ancora senza Shout/PCS/altri consumer | O=0 | O=150 | O=300 |
|---|---:|---:|---:|
| Righe Fp3 delle sole riduzioni RNE, lower | 152.372 | 152.852 | 152.852 |
| Correzioni COPE per tali RNE, byte | 2.106.390.528 | 2.113.026.048 | 2.113.026.048 |
| Con i contatori del range W, byte COPE | 3.012.346.368 | 3.018.981.888 | 3.018.981.888 |
| Output di campo PRF del solo prover COPE, lower | 753.086.592 | 754.745.472 | 754.745.472 |

Sono quote di fabbisogno, **non una distribuzione del bootstrap sui turni**.
Nel setup unico B12 tutte arrivano prima della prima risposta:
**P1 ≥9.050.310.144 byte**, oltre 130 MB e persino oltre i 210 MB complessivi.
Il fattore resta `3*576*8` byte/Fp3; gli output PRF sono `2*576*3` per
riga Fp3, non istruzioni AES o secondi. Sono esclusi dal lower sacrifici,
OT, seal, setup metadata, terminali RNE, altre correlazioni e tutto il corpo;
nessuna di queste voci è gratuita. Il solo Shout non rende compatto COPE.

| Altra voce dello screen locale | Conto e disposizione |
|---|---|
| Memoria globale | W packed 61.394.690.560 byte già nel riferimento. Gli hint deterministici W/Γ possono essere globali; nessun nuovo setup completo è istanziato o valutato a zero |
| Memoria dinamica residua | `range::prove` conserva `48*(2*N-1)` byte di albero: **3.298.534.883.280** per W/D35, **1.649.267.441.616** per A/D34. Ciascuno eccede arena e HBM, anche eseguendoli in sequenza |
| Traffico e passaggi residui | Almeno **4.947.802.324.896 byte di scritture** per i due alberi, più letture figli e fold. Costruzione di 35/34 livelli; GKR di 595/561 round. Getter, PCS, copie, serializzazione e replay si aggiungono |
| Banda e budget | Alla sensibilità sequenziale già motivata di 2,68 TB/s, quelle sole scritture valgono 1,85 s **ipotizzando memoria sufficiente**, non un tempo realizzabile. Spostarle fuori HBM è vietato; persino una scrittura a 50 GB/s esterni costerebbe 98,96 s. Il budget esterno resta ≤35 s, riservandone 15 al resto |
| Tempo completo e lavoro | Upper completo **ignoto**, sia per la sostituzione che per una composizione più ampia. Nessun vantaggio su setup + tutti i prefissi 1/2/3 è dimostrato. Il rifiuto per memoria/byte è già decisivo; nessun benchmark è necessario |

L'albero W dipende da `alpha` derivata **dopo** i contatori autenticati:
anche su W fisso non è materiale globale. Non si trasferisce questo lower
a un diverso algoritmo di range; vale proprio per il componente conservato.

**Dipendenza da chiarire prima di riaprire Shout.** Serve un bootstrap
compatto fresco, con parametri malevoli Fp3 e costi completi, oppure una
schedule che riduca anche quelle correlazioni residue. B11 può essere un
seed bootstrap di un'espansione diversa, ma quella trasformazione richiede
conteggi e riduzione propri; riusare il vecchio PCG B7 intero non risolve
il suo fallimento. Anche un bootstrap idoneo lascia aperti range e PCS
entro arena, disponibilità di A/replay e costo totale non crescente.

Sul lato Shout, §§4.1/6 del [paper conservato](../../sota/2025-0105-twist-shout.md),
resta necessaria l'apertura del polinomio one-hot fissato prima delle sfide:
`ra(tau,r) = sum_i eq(r,i)*eq(tau,bits(A_i))` non è una forma lineare
nei byte A. L'apertura del solo `A(r)` e un nuovo MAC libero non la
sostituiscono. I pesi/lane delle 892 RNE e le tabelle combinate dopo FS
richiedono inoltre il proprio collegamento, già censito sopra. Una prova
privata di questa relazione è il contributo da valutare, senza una nuova
PCS per token e senza riaprire il layout one-hot denso respinto.

Riusabili fra sessioni sono solo hint privati deterministici W/Γ e setup
pubblico indipendente dal verifier; resta da provare la vista congiunta
same-W/ZK con risorse globali. Il riuso lineare degli originali può usare
`Mac.Valid.add/smul/sum` di [security §6](security.md#6-risorse-riuso-formale-e-confine-runtime);
il nuovo one-hot, FS e simulatore non ereditano i bound B12. Correlazioni,
pad e sali a esposizioni finite restano freschi. **Capacità supportata nel
contratto completo: nessuna; capacità sottoposta allo screen: tre risposte.**

## Bootstrap fresco: Dory alimentato da B11

**Screen analitico del 2026-09-12, senza credito di protocollo o hardware.**
La verifica minima legge Dory **PCG** §4.2/Fig. 5, §5.2/Tab. 2 e
Appendice C nel [Markdown conservato](../../sota/2025-1660-dory-streaming-vole.md);
la [pagina primaria](https://eprint.iacr.org/2025/1660) identifica la versione
del 2025-09-23. **La deroga successiva a 130 MB elimina il rifiuto per
il solo seed delle tre geometrie pubblicate.** Si ricontano capacità e
byte residui; la famiglia non acquisisce sicurezza, tempo o certificato
completo dal solo margine di trasporto.

Si considerano F=Goldilocks, K=Fp3, grado μ=3 e un solo setup fresco.
Nel paper P0 è il verifier DV, P1 il prover, con M=K+Δ*x; si applica
Δ_native=−Δ_paper come nel [packing esistente](../../rust/volta-pcs/src/c71_matrix/gemma/native/pool.rs).
Una riga B11 ha già x in F e tag/key in K: **un seed sVOLE costa una
riga base**, non tre. Tre output base disgiunti sotto la stessa Δ danno
invece una correlazione Fp3 completa, mediante 1,u,u².

Con t blocchi e h=log2(N/t), Fig. 5 consuma
`s=t*(h+1)+3` righe seed: t payload β, t*h maschere dei cammini e tre
maschere del check. Non basta contare soltanto β. Dopo B11, il prover
invia d,z per `8*(t*h+3)` byte; il verifier invia c per `24*t*h` byte.
Sono payload, prima di framing, F_Rand e F_EQ. B11 aggiunge almeno
`4608*s` byte ricevuti dal verifier per COPE; il wire B11 nelle **due
direzioni**, seal incluso, è `233345+4680*s`, dal
[conteggio esistente](../../scripts/c7_1_gemma_plan.py) `b12_fixed_run_bootstrap`.
Quel seal non certifica già il nuovo setup Dory: occorre un completamento
del protocollo composto prima di rendere disponibili gli output.

| Geometria Tab. 2, solo trasposta per il conto | t / h | Capacità n base pubblicata | Seed s a μ=3 | Solo COPE ricevuto, byte | d,z / c, byte |
|---|---:|---:|---:|---:|---:|
| LPN1 | 1.194 / 13 | 1.956.249 | 16.719 | 77.041.152 | 124.200 / 372.528 |
| LPN2 | 1.571 / 15 | 10.295.705 | 25.139 | 115.840.512 | 188.544 / 565.560 |
| LPN3 | 1.120 / 18 | 58.720.256 | 21.283 | 98.072.064 | 161.304 / 483.840 |

Sommando il wire B11 con seal e i payload d,z,c si ottengono nelle **due
direzioni** 78.974.993/118.637.969/100.482.929 byte: restano rispettivamente
51.025.007/11.362.031/29.517.071 byte rispetto ai 130 milioni. Questo è
un confronto prudente che conta anche l'outgoing del verifier, non un
upper del bootstrap o del certificato: F_Rand/F_EQ e loro framing, il
completamento Dory, metadata/installazione e corpo R1 vanno aggiunti.
Nessun residuo è un budget assegnato a una PCS o al consumer Shout.

La Tab. 2 è un profilo COT F2/F_(2^128), **non parametri di sicurezza
Goldilocks/Fp3**. Il lower conta soltanto quelle geometrie con il seed
B11; omette persino i nove sacrifici COPE, OT e corpo della risposta.
Anche la capacità va distinta: i soli residui RNE+istogrammi W richiedono
1.964.043 righe base, già più di LPN1; B12 completo richiede 11.466.948,
più di LPN2. Il nuovo fabbisogno Shout/range/PCS non è ancora censito.
Non si divide il seed sui tre turni e non si riusano i suoi output.

**Finestra numerica, non nuova selezione.** §4.2 ammette rumore regolare
nonzero per campi grandi, con correzioni β aggiuntive; §5.2 distingue
questo caso dal rumore binario rilassato. Non si dimezza t attribuendogli
automaticamente i 128 bit pubblicati. Prima di cercare un parametro,
indicando con R1 il nuovo corpo e con U gli altri byte ricevuti ancora
da contare, sono necessarie entrambe le disuguaglianze

```text
4608*(t*(h+1)+3) + 8*(t*h+3) + R1 + U <= 130.000.000
floor(t*2^h/5) >= n_richiesto                     [se si mantiene N≈5n]
```

U include sacrifici/OT/check/seal/metadata e l'eventuale correzione β;
non è zero. Usando 11.466.948 soltanto come capacità di confronto,
R1=U=0 dà gli intervalli **necessari** t=875..1656 per h=16,
438..1564 per h=17, 219..1482 per h=18. Non sono parametri LPN ammessi:
mostrano dove una verifica di sicurezza avrebbe utilità, evitando di
escludere la famiglia per il solo costo delle geometrie binarie.

**Obblighi che impediscono di chiamarlo bootstrap compatto risolto:**

- Il Teorema 1 usa EA-LPN **con leakage statico**, F_sVOLE, F_Rand,
  F_EQ e una **permutazione casuale programmabile su K**. Servono una
  realizzazione malevola dei funzionali e un bound concreto composto,
  con risorse dell'Appendice C, nel modello T80/M80/Q64 corrente.
  I 128 bit stimati contro attacchi LPN non sono quel bound di vantaggio.
- `H(x)=π(σ(x))+σ(x)` e figli `H(x), x−H(x)` sono il cGGM del paper.
  AES-256 ha blocchi di 128 bit, K ha circa 192 bit: né AES applicato
  direttamente né il GGM B11 a seed di 32 byte istanziano quel teorema.
  ROM SHAKE e permutazione programmabile non sono la stessa primitiva.
  Nuove ipotesi o un nuovo costruttore richiedono una riduzione dichiarata;
  non vengono aggiunti alle ipotesi selezionate di B12.
- Il costo di inizializzazione pubblicato è circa **2N espansioni per
  ruolo**, più universal hashing su N elementi; l'ottimizzazione a N
  per il prover è specifica di F2. L'output richiede fino a ℓ*h visite
  cGGM per riga base, tre volte per Fp3. Non sono istruzioni AES o secondi
  H100. Le chiavi compatte non cancellano quei due passaggi iniziali.
  B11, chiavi/cammini, hash streaming, output vivi e scratch sono memoria
  di sessione da contare insieme entro arena; il solo `O(t*h)` non è
  un upper completo. Traffico e tempo completo restano ignoti.
- Tutto il materiale Dory dipendente da Δ/rumore resta fresco e privato
  della sessione. FRand/check devono seguire i messaggi che controllano;
  burn, NoPeek, abort e seal devono precedere l'uso delle correlazioni.
  L'espansione non autentica da sola il one-hot Shout contro A, né risolve
  range/PCS o il riuso globale multi-sessione di W.

**Prossimo lavoro utile:** chiarire una realizzazione concreta del cGGM e
un'istanza EA-LPN-SL su campo grande dentro la finestra, oppure ridurre il
fabbisogno con una schedule diversa. Un seed alternativo a B11 può cambiare
il lower, ma richiede il proprio costo e simulazione malevola. Il vecchio
PCG B7, il refill con righe già consumate o un setup dipendente da Δ
classificato globale non sono sostituzioni ammesse. Shout resta subordinato
a questa verifica; range/PCS entro arena e legame privato agli originali
restano obblighi indipendenti. Nessun tempo <=50 s o lavoro totale non
crescente sui prefissi 1/2/3 è acquisito.

### Realizzazione cGGM: cosa trasferisce Half-Tree

La [fonte primaria Half-Tree](https://eprint.iacr.org/2022/1431), revisione
2023-12-21, è ora conservata in [Markdown](../../sota/2022-1431-half-tree.md).
§4.1.2 e Appendice B.2/Teorema 7 confermano il ramo usato da Dory:
nodi nel campo K, permutazione su **quello stesso K**, sicurezza
semi-onesta del single-point in RPM. La sicurezza malevola streaming
proviene poi dal check e dalla riduzione di Dory, non dal solo Teorema 7.

L'invariante decisivo è `left+right=parent` in K: per induzione la somma
delle foglie di un sottoalbero è il suo nodo. Dory usa proprio questa
identità in `Acc/PuncAcc` per evitare di riespandere tutte le foglie.
Il GGM B11 produce due seed pseudocasuali indipendenti: convertirli in
Fp3 non impone quell'identità. Cambiare soltanto il generatore dentro
`Acc` non è quindi una sostituzione corretta. La primitiva deve conservare
sia l'invariante sia la simulazione con Δ nell'output onesto del verifier.

§4.2 offre un altro ramo, **pcGGM**, con nodi binari e conversione finale
in un K arbitrario. Questo risolve il tipo del campo delle foglie per il
single-point, ma il paper applica un hash finale proprio per **rompere
la correlazione dell'ultimo livello**. Non fornisce la somma delle foglie
Fp3 dalla radice binaria; non si trasferisce dunque l'accumulo streaming
Dory dal nome Half-Tree o dal costo AES del pcGGM. Costruire e conservare
somme Fp3 ausiliarie richiederebbe un nuovo conteggio di setup e memoria,
mentre rigenerarle richiederebbe un nuovo bound dei passaggi.

Non è dimostrata un'impossibilità di un cGGM nel ROM o con AES. È escluso
il port letterale delle due alternative esaminate; una costruzione di
permutazione su Fp3 nel ROM, oppure una prova diretta del cGGM con un
altro hash, resta una verifica crittografica distinta. Non basta una
permutazione invertibile o un test di uguaglianza dei MAC per concluderla.

### Check per blocco: compatibilita con il leakage dichiarato

**Nuovo risultato componente, non bootstrap ammesso.** Dory Def. 2
consente al distinguisher di scegliere t insiemi I_i e ricevere un solo
bit per `alpha in product(I_i)`. In Appendice C, Lemma 2, Hybrid 2,
il check unico definisce invece `I_v={alpha: U(g(alpha))=v}`. Questo
insieme non è automaticamente cartesiano. Inoltre alpha e alpha′
sono scelti condizionando sulla stessa U: l'epsilon-universalità per
due vettori fissati **prima** di U non si applica direttamente al
passaggio che precede (11). Serve un argomento aggiuntivo; non si
trasferisce quel solo epsilon al bound C7.1.

Il [controllo finito](../../tests/test_c71_dory_split_check.py) ricostruisce
i vettori di key modificati (8)–(10) su due blocchi da quattro foglie,
K=F5, con H nella forma Half-Tree. Un checksum di livello alterato
produce due classi di cammini per blocco. Una possibile U congiunta
accetta le coppie di classi (0,0) e (1,1), ma non (0,1): le proiezioni
sono complete e il prodotto contiene anche cammini respinti. Il test
enumera inoltre tutte le 625 hash lineari del singolo blocco. È un
controesempio al trasferimento automatico dell'insieme di accettazione,
**non un attacco al PCG completo** o una confutazione di ogni sua riduzione.

**Variante da valutare: t check con un solo esito finale.** Sostituire
U:K^N→K con una U_i:K^B→K per blocco, B=N/t=2^h, e usare tre maschere
base fresche per ciascuno. Si confrontano i t valori mediante **un'unica
F_EQ vettoriale**, che espone soltanto l'AND finale. Non si pubblicano
i singoli esiti, il primo blocco errato o un arresto indicizzato: tali
emissioni non sono il bit di leakage della Def. 2. Tutti i c,d sono
fissati prima delle U_i; F_Rand rimane una premessa da realizzare.

Il punto utile è che, per ogni blocco e ogni cammino candidato a, il
vettore g_i(a) è fissato senza conoscere il payload beta. Con i segni
del paper, dalle righe seed e dal d già inviato:

```text
M(beta) = K(beta) + beta*Delta
M(s_j) = K(s_j) + (d_j + a_j*beta)*Delta
M(r_j) = a_j*K(beta) - K(s_j) - d_j*Delta.
```

Il patch della foglia sottrae beta*Delta e lascia K(beta) meno le altre
foglie. Quindi g_i(a) dipende soltanto da key seed, Delta, d,c, hash
dell'albero e a, tutti fissati prima delle U_i. La convenzione che
complementa i bit del cammino non cambia questa proprietà.

**Lemma condizionale sui check.** Se le U_i sono hash lineari uniformi
fresche su K, indipendenti da questi vettori, tranne che con probabilità

```text
epsilon_split <= t * binom(B,2) / |K|,
```

ogni fibra accettata `I_i={a: U_i(g_i(a))+offset_i=v_i}` contiene un
solo **vettore g_i**, anche se più cammini lo producono e v_i viene
scelto dopo U_i. Infatti una coppia con vettori diversi collide con
probabilità 1/|K|; un'unione sulle al più binom(B,2) coppie per blocco
vale simultaneamente per tutti i v_i. Fuori da questo evento si sceglie
un rappresentante canonico di ogni I_i non vuoto. Ogni cammino accettato
produce gli stessi vettori di key e gli stessi accumuli. L'evento di
accettazione è ora esattamente `alpha in product(I_i)`: questo scarica
il particolare collegamento alla **forma** della Def. 2, non l'ipotesi
EA-LPN-SL o la simulazione dell'altro ruolo.

Il rappresentante si trova enumerando B cammini per blocco, senza
enumerare B^t combinazioni o campionare condizionatamente su un insieme
congiunto. La ricostruzione diretta costa O(t*B²) posizioni di foglie:
per LPN3 sono 76.965.813.944.320. È lavoro del riduttore da contabilizzare,
non lavoro onesto, una misura o un'esecuzione locale autorizzata.
Per LPN3 il lemma dà **146,87 bit** nel modello con coin fresche.
Applicare meccanicamente il fattore Q*=2^74 lascia **72,87 bit**, sotto
78: non si realizza F_Rand dicendo soltanto «Fiat–Shamir». Il bootstrap
offline interattivo è ammesso dal contratto, con byte/tempo e abort contati.

**Costi necessari della variante, alle geometrie già censite.** I seed
diventano `s_split=t*(h+4)`; d,z costano `8*t*(h+3)` byte ricevuti dal
verifier, c costa ancora `24*t*h` nella direzione opposta. In questo
masking lineare servono tre maschere per blocco per nascondere tutti i check;
riusare le tre maschere globali non conserva quella privacy.

| Geometria | Seed base | COPE+d/z ricevuti, lower | B11 con seal+d/z/c, due direzioni | Margine su 130 MB prima delle voci mancanti |
|---|---:|---:|---:|---:|
| LPN1 | 20.298 | 93.686.016 | 95.753.345 | 34.246.655 |
| LPN2 | 29.849 | 137.770.416 | 140.718.449 | già esclusa dal lower ricevuto |
| LPN3 | 24.640 | 113.729.280 | 116.220.545 | 13.779.455 |

F_Rand/F_EQ vettoriale, completamento Dory, metadata/installazione e R1
restano aggiuntivi. Capacità e sicurezza LPN su campo grande conservano
i limiti dello screen precedente: solo LPN3 copre il riferimento B12.
Anche concedendo Shout gratuito, **LPN3 con questi check e PCS/altro corpo
B12 invariati supera 130 MB**: il lower del corpo privato dei soli P/S
RNE è `47.841.180-25.210.128=22.631.052` byte, dai
[conteggi canonici](../../scripts/c7_1_gemma_plan.py). Aggiungendo il lower
ricevuto del bootstrap si ottengono **136.360.332 byte**. Non si trasferisce
questo rifiuto a un'altra PCS, a un altro range o a nuovi parametri LPN.

**ROM e prossimo passo.** La [fonte primaria sul cGGM nel ROM](https://eprint.iacr.org/2024/1004),
§3.1/Fig. 1 nel [Markdown conservato](../../sota/2024-1004-relaxed-vector-commitment.md),
costruisce figli `H_tree(salt,livello,posizione,x)` e `x XOR H_tree(...)`.
Conferma che la correlazione può essere studiata nel ROM senza una
permutazione. I suoi lemmi riguardano però semi-binding/hiding di un
commitment binario; non la generazione DV con key nell'output onesto.
La revisione 2025-11-20 corregge inoltre la precedente variante con root
derivata dalla chiave di firma: non se ne importa quel riuso.
Il [controllo dei cammini non binari](#cammino-finale-non-binario-check-e-recupero-della-chiave)
qui sotto aggiunge un obbligo alla simulazione e respinge una particolare
istanza RPM. L'invariante additivo da solo non fornisce una prova nel ROM,
un'espansione AES, il bound completo del riduttore o i 50 s onesti.

### Cammino finale non binario: check e recupero della chiave

**Derivazione locale sulle formule della fonte, non nuovo protocollo.**
La [versione primaria Dory](https://eprint.iacr.org/2025/1660) del
2025-09-23, Fig. 5 e Appendice C/Lemma 3, assume che un r non binario
con beta nonzero provochi abort salvo errore trascurabile. Il caso in
cui soltanto **l'ultima** coordinata r appartiene a F\{0,1} richiede
invece un estrattore diverso, anche con coin realmente uniformi.

Fissare un blocco, a=K(beta), M_beta=a+beta*Delta. Il prefisso del
cammino è binario; il prover conosce tutti i sottoalberi fuori da quel
prefisso. Sia S la somma delle loro foglie e x=a−S il padre delle due
foglie ancora nascoste. Dall'ultima correzione, sottraendo M(r) e le
foglie sinistre già note, il prover ricava

```text
L = H(x) - r*a.
K_left  = L + r*a;        K_right = -S-L + (1-r)*a
e_left  = r*beta;         e_right = (1-r)*beta
M_left  = L + r*M_beta;   M_right = -S-L + (1-r)*M_beta.
```

Entrambe le identità `M=K+e*Delta` sono esatte, per **qualsiasi H** e
qualsiasi K estensione di F. Il prover calcola e,M senza Delta; fuori
da queste due foglie usa e=0 e i nodi noti. Per beta nonzero il rumore
ha due punti, anziché uno. Con `z=m+coords(U(e))` e
`w=U(M)+sum_j M(m_j)*u^j`, il check della Fig. 5 accetta per **ogni U**.
Anche i check per blocco accettano. L'argomento della fonte che considera
un valore della foglia indipendente dal valore indovinato non copre la
compensazione mediante z, scelto dopo U. Non serve indovinare Delta per
questo solo passaggio.

Questo fatto **da solo non rompe F_sPCG-sVOLE**: quando P1 è corrotto,
Fig. 4 gli permette output x,M arbitrari, non soltanto rumore regolare.
La simulazione deve estrarre i due pesi e i relativi MAC; la linearità
conserva tutti gli accumuli. Non può però abortire incondizionatamente
su quest'ultimo r non binario come l'estrattore citato. Il caso di una
coordinata non binaria a livelli precedenti rimane distinto e aperto.

**Esclusione concreta in RPM: sigma scalare nel campo base.** Il
Teorema 1 e la nota 2 consentono `sigma(y)=c*y` con c in K\{0,1}.
Se si sceglie c in **F\{0,1}**, il prover sceglie r=c. Poiché
`H(x)=pi(c*x)+c*x`, l'osservazione precedente diventa

```text
L + c*S = pi(c*x)
x = c^(-1) * pi^(-1)(L+c*S)
a = x+S;                 Delta = (M_beta-a)/beta.
```

Una sola query inversa recupera Delta esattamente, condizionatamente
a beta nonzero. Con seed onesto questo evento ha probabilità 1−1/|F|;
non è una ricerca su |K| chiavi. Una volta nota Delta il prover può
calcolare tutte le key dai suoi seed, ricostruire l'albero e superare
il check anche usando un rumore single-point scelto da lui. Il problema
precede F_Rand/F_EQ e non si corregge aumentando maschere o ripetizioni.
**Non si porta dunque il ramo RPM con sigma=2*id su Fp3**: 2 è una
scelta formalmente ortomorfa in caratteristica Goldilocks, ma insicura
contro questo prover. Il risultato non riguarda l'implementazione COT
binaria della fonte, dove quel r non binario non esiste, né B11/B12.

Il [test finito riproducibile](../../tests/test_c71_dory_nonbinary_path.py)
costruisce due livelli da seed MAC validi su F5 e distingue la vista del
prover dalle key del verifier. Controlla tutti i 625 hash lineari per
ciascun ultimo r non binario e Delta, inclusi gli accumuli, poi il
recupero di Delta per **tutte le 120 permutazioni**, tutti i Delta,
beta nonzero e prime correzioni. Non è un benchmark, un test del
bootstrap nativo o una prova di sicurezza su campo piccolo. Le identità
sopra, non la dimensione del test, estendono il risultato a Fp/Fp3.

**Alternative per il solo caso beta nonzero.** Il ROM diretto non fornisce
l'oracolo inverso usato nell'attacco, ma conserva le due foglie accettate.
Nel ramo RPM, sigma(y)=u*y con u in Fp3\Fp evita questa cancellazione
scalare: per ogni r in Fp, sigma−r*id è invertibile. Questa proprietà
permette di risolvere l'equazione di una query inversa in un *candidato*
a, da validare con l'interfaccia di guess; non rivela a da L da solo.
Non è ancora una riduzione: vanno trattati i livelli precedenti, i
transcript adattivi e l'output Delta del verifier dopo il check. Nessuna
permutazione concreta su Fp3 o nuova assunzione è selezionata. Prima di
questo trasferimento va inoltre risolto il caso beta=0 qui sotto.

### Payload zero: controllo necessario prima delle correzioni

**Il ramo letterale della Fig. 5 con beta zero ammesso è escluso anche
nel ROM.** Non basta cambiare sigma. Per un blocco con h>=2 e beta=0,
il prover conosce a=K(beta)=M(beta). Sceglie `d_j=s_j` a tutti i livelli
salvo l'ultimo, dove sceglie `d_last=s_last-1`. Qui s_j indica il seed
della maschera di cammino, distinto dal payload beta. Con i segni della fonte,

```text
K(r_j) = -K(s_j)-d_j*Delta = -M(s_j)+(s_j-d_j)*Delta
k = c_0-K(r_0) = c_0+M(s_0)
Delta = c_last + M(s_last) - sum_left_last.
```

L'offset a e la prima root k sono quindi noti. Il prover riespande tutto
l'albero con sole query **forward**, calcola sum_left_last e recupera
Delta dall'ultima correzione prima di F_Rand/F_EQ. Il lavoro è O(B),
senza oracolo inverso o ipotesi su H. Con Delta può poi ricostruire le
key seed e produrre un check accettato; un controllo tardivo non ripara
l'esposizione. Il [test](../../tests/test_c71_dory_nonbinary_path.py)
enumera tutti gli hash F2→F2 e F5→F5, tutti i Delta e c_0, da seed MAC
validi. La derivazione vale anche su Fp/Fp3; non è una verifica del codice
COT pubblicato, il cui protocollo implementato non è stato ispezionato.

La Fig. 2 consente al receiver corrotto di scegliere beta=0. Anche se il
backend imponesse beta uniformi oneste, con t=1120 la probabilità di
almeno uno zero è `1-(1-1/p)^t`, circa **2^-53,87**: non si può assorbire
fra gli errori da 78 bit. La distribuzione regolare rilassata della fonte
include zero. Escluderlo richiede un vincolo verificato **prima di c**,
non una promessa del prover o il test locale `if beta == 0`.

**Riparazione candidata con il batch prodotti esistente.** Il prover
campiona beta_i esattamente in F* prima di leggere le righe seed da
correggere, e fissa eta_i=beta_i^(-1). Trasferisce beta sui t seed payload
già contati e eta su t righe base aggiuntive, con **2t correzioni Fp**.
Non si usa una mappa zero→1 attribuendole la distribuzione uniforme F*.
Sampler, loro abort e transcript rimangono da istanziare e contare.
Una maschera Fp3 disgiunta costa altre tre righe base. Il verifier
controlla i t prodotti sui **MAC originali corretti**, con costante 1
pubblica, mediante il [batch già presente](../../rust/volta-pcs/src/c71_matrix/range.rs).
Non serve una PCS per questi vettori residenti o un sumcheck per blocco.
Tutti i seed e le correzioni sono fissati prima di lambda; nessun c Dory
viene rilasciato finché il controllo non accetta.

Usando qui i segni **nativi** `k=m+Delta*x`, il prover invia soltanto
due scalari Fp3, 48 byte, per una maschera fresca (rho,m_rho):

```text
A = rho   + sum_i lambda^i * (beta_i*m_eta_i + eta_i*m_beta_i)
B = m_rho + sum_i lambda^i * m_beta_i*m_eta_i
B+Delta*A == k_rho + sum_i lambda^i*(k_beta_i*k_eta_i-Delta^2).
```

Il prodotto pubblico 1 ha tag zero e key Delta, senza nuova riga.
La differenza è `Delta^2*sum_i lambda^i*(beta_i*eta_i-1)` per il wire
calcolato dal prover. Un wire alterato può aggiungere solo termini di
grado <=1 in Delta. Nel modello MAC ideale, con Delta nascosto e lambda
uniforme dopo i valori fissati, il consueto argomento di radici dà
`(t-1)/|K| + 2/|K|`; non un bound composto B11→Dory. La maschera fresca
nasconde A; dato lo stato del verifier, l'equazione determina B.
Il [controllo finito](../../tests/test_c71_dory_nonzero_precheck.py)
verifica identità, rifiuto dello zero e gradi delle due equazioni.
FS, NoPeek e simulazione congiunta vanno collegati alla nuova schedule;
non si trasferiscono automaticamente i bound B12.

**Nuovo costo parziale.** Aggiungendo questo precheck alla variante con
check per blocco, `s=t*(h+5)+3`. I payload ricevuti d/z/correzioni beta/eta
e precheck sono `8*t*(h+5)+48` byte, oltre COPE; c costa ancora `24*t*h`
nella direzione opposta. Per la geometria LPN3:

| Voce | Byte o righe |
|---|---:|
| Seed base B11 | 25.763 righe |
| COPE e payload ricevuti, lower | 118.922.032 byte |
| B11 con seal e payload, due direzioni | 121.494.153 byte |
| Margine parziale su 130 MB | 8.505.847 byte |
| Lower ricevuto con PCS/altro corpo B12 conservato | 141.553.084 byte |

Coin/check finali, completamento, metadata e corpo restano fuori dal
sottototale. La nuova distribuzione F* richiede i propri parametri LPN:
le geometrie binarie della Tab. 2 non diventano per questo sicure.
Il precheck elimina questo specifico ingresso zero; non elimina il
recupero con sigma scalare, né dimostra la simulazione dei cammini non
binari. **Prossimo lavoro:** cGGM concreto e riduzione malevola sotto il
vincolo verificato beta nonzero, prima di approfondire Shout. L'arena,
il legame agli originali e il tempo completo restano obblighi aperti.

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
assert all(b > cap for b, cap in zip(wire, (130_000_000, 40_000_000, 40_000_000)))
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
assert [cap//13_824 for cap in (130_000_000, 40_000_000)] == [9403, 2893]

# Dory Fig. 5: Fp/Fp3 seed rows; no protocol execution or parameter admission.
geometries = [(1194, 13), (1571, 15), (1120, 18)]
seeds = [t*(h+1)+3 for t, h in geometries]
assert seeds == [16719, 25139, 21283]
assert [4608*s for s in seeds] == [77041152, 115840512, 98072064]
assert all(4608*s < 130_000_000 for s in seeds)
assert [8*(t*h+3) for t, h in geometries] == [124200, 188544, 161304]
assert [24*t*h for t, h in geometries] == [372528, 565560, 483840]
subtotals = [233345 + 4680*s + 8*(t*h+3) + 24*t*h
             for s, (t, h) in zip(seeds, geometries)]
assert subtotals == [78974993, 118637969, 100482929]
assert [130_000_000-b for b in subtotals] == [51025007, 11362031, 29517071]
capacities = [t*2**h//5 for t, h in geometries]
assert capacities == [1956249, 10295705, 58720256]
residual_base_rows = 3*sum(8*c+892+65535 for c in (18935, 18995, 18995))
assert residual_base_rows == 1_964_043 > capacities[0]
assert capacities[1] < 11_466_948 < capacities[2]
windows = []
for h in (16, 17, 18):
    lower = (5*11_466_948 + 2**h-1)//2**h
    upper = (130_000_000 - 4608*3 - 24)//(4608*(h+1)+8*h)
    windows.append((lower, upper))
    assert (lower-1)*2**h//5 < 11_466_948 <= lower*2**h//5
    cost = lambda t: 4608*(t*(h+1)+3)+8*(t*h+3)
    assert cost(upper) <= 130_000_000 < cost(upper+1)
assert windows == [(875, 1656), (438, 1564), (219, 1482)]

# Separate block checks, one final equality result; still no PCG admission.
from fractions import Fraction
split_seeds = [t*(h+4) for t, h in geometries]
split_received = [4608*s + 8*t*(h+3)
                  for s, (t, h) in zip(split_seeds, geometries)]
split_subtotals = [233345 + 4680*s + 8*t*(h+3) + 24*t*h
                   for s, (t, h) in zip(split_seeds, geometries)]
assert split_seeds == [20298, 29849, 24640]
assert split_received == [93686016, 137770416, 113729280]
assert split_subtotals == [95753345, 140718449, 116220545]
assert split_received[1] > 130_000_000
assert 130_000_000-split_subtotals[2] == 13_779_455
t, h = geometries[2]
err = Fraction(t*2**h*(2**h-1), 2*p**3)
assert Fraction(1, 2**147) < err < Fraction(1, 2**146)
assert (1 << 74)*err > Fraction(1, 1 << 78)
assert t*2**(2*h) == 76_965_813_944_320
assert split_received[2]+47_841_180-25_210_128 == 136_360_332 > 130_000_000

# A zero payload cannot be charged as a <=2^-78 event for honest Fp seeds.
zero_lower = Fraction(t, p)-Fraction(t*(t-1), 2*p*p)
assert Fraction(1, 2**54) < zero_lower <= Fraction(t, p) < Fraction(1, 2**53)
# Candidate nonzero guard: t inverse rows, one Fp3 mask, two Fp corrections
# per block and two Fp3 wire scalars; all are ADDITIONAL to split checks.
guard_seeds = t*(h+5)+3
guard_received = 4608*guard_seeds + 8*t*(h+5)+48
guard_subtotal = 233345+4680*guard_seeds+8*t*(h+5)+24*t*h+48
assert guard_seeds == 25763
assert guard_received == 118_922_032
assert guard_subtotal == 121_494_153
assert 130_000_000-guard_subtotal == 8_505_847
assert guard_received+47_841_180-25_210_128 == 141_553_084 > 130_000_000
# Only the ideal product-check term, NOT a complete FS or bootstrap bound.
assert 2**74*Fraction(t+1, p**3) < Fraction(1, 2**107)
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
| [Half-Tree](../../sota/2022-1431-half-tree.pdf), `https://eprint.iacr.org/2022/1431.pdf` | `abf39d5084c369e7926da59aca712aa252a1cfd97c79fb6c31d6e2eea7bb778f` / `3dd7bf0cdfe1a6f22308e779460c888325583c5af914ba6022b25c88f87f3327` |
| [Relaxed Vector Commitment](../../sota/2024-1004-relaxed-vector-commitment.pdf), `https://eprint.iacr.org/2024/1004.pdf` | `7d401823a18e049ed6d068b92e4d1ca625eeed87b4c39628b507b8ab996cb699` / `22b9c1db9227ba0c082174caf97eba5e427990cd74eca71f9e079d41e0f13b77` |
