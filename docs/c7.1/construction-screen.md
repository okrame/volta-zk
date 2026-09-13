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
Il [bootstrap fresco](#bootstrap-fresco-dory-alimentato-da-b11) ha ora una
candidata completa delle primitive censite da 61,84 MB; il proprietario
ha ora autorizzato EA-LPN-SL-reg* al bound concreto del design. Lo screen Shout viene quindi
riaperto soltanto sul piano analitico. Non si avvia un'implementazione.

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
Se sono sei letture dirette di W, dal 2026-09-13 il loro numero non
le esclude; resta da chiudere il costo del calcolo e dello schedule. Il paper migliora i prodotti generici,
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

### PCS private recenti: tre port letterali respinti

Queste fonti sono state lette per il requisito preciso «valutazione legata
agli originali senza rivelarla al verifier». Le loro nozioni di privacy non
coincidono con quell'endpoint DV e nessuna fornisce il ponte VOLE-MAC.

| Fonte | Disallineamento decisivo | Screen di risorse |
|---|---|---|
| [Blind PCS RAA 2026/487](../../sota/2026-0487-bootstrapping-free-blind-pcs.md) | Il verifier possiede la secret key BFV, decripta colonne aperte e risposta e verifica in chiaro (§6.1/App. B). Nasconde i dati al prover del PCS, non la valutazione al designated verifier C7.1 | Usa `q=65537`, grado ring `2^14` e `ell=843` per 128 bit per-proof. Il paper misura circa **32 MB** a N=`2^20` e **105 MB** a N=`2^22`; il secondo eccede già il residuo iniziale di 24,22 MB, prima del ponte Fp3, range e consumer. Il fattore ROM globale C7.1 richiederebbe inoltre un nuovo parametro, non `ell=843` |
| [Private polynomial commitments 2023/680](../../sota/2023-0680-private-polynomial-commitments.md) | Il prover opera su un polinomio cifrato AHE e produce una valutazione cifrata; le identità sono in gruppi bilineari sotto DLIN/DPP. Non termina in un valore Fp3 autenticato e nascosto al verifier senza una nuova 2PC | A grado `2^16`, una apertura costa **701 s** prover e 53,7 s verifier; `2^16` aperture costano 242.395 s e 6,1 MB. Campo/gruppi e tempo escludono il port letterale prima della memoria |
| [Greyhound 2024/1293](../../sota/2024-1293-greyhound.md) | Hiding/HVZK mascherano commitment e termini ring, mentre la sintassi della valutazione conserva `y=f(x)` nello statement. La riduzione usa ring ciclotomici e l'ipotesi `q congruent 5 mod 8`; Goldilocks è `1 mod 8`, quindi parametri e teoremi non si trasferiscono | A N=`2^30` il benchmark CPU pubblica 132 s commit, 41,2 s prove e 2,80 s verify. Una decomposizione bilineare rank-5 può ridurre la MLE Fp3 a cinque forme base, ma non crea hiding dell'endpoint, range per coordinata o un commitment omomorfo rispetto al MAC con Delta segreto |

Il commitment Greyhound usa decomposizioni gadget con carry: non è lineare
nel messaggio nel senso necessario per uguagliare direttamente un'apertura a
`k=m+Delta*x`. Anche concedendo le cinque forme, servirebbero nuovi teoremi
per hiding dell'evaluation, batching, range e composizione DV. Analogamente,
il nome «blind» di 2026/487 riguarda verifiable FHE: il possessore della
chiave di decrittazione vede proprio i valori che C7.1 deve tenere privati.
Le tre linee restano `credit:false`; non si implementano wrapper.

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

Il confronto MAC a due chiavi del bootstrap non ripara questo punto.
Akita usa `v` nello statement pubblico e trasmette già nei fold partial,
risposte e stato terminale dipendenti dal witness. Sostituire soltanto il
check finale con `(Delta0+Delta1)*(y-x)=0` nasconde il confronto, non quel
transcript. Per simulare dal solo bit occorrerebbe mascherare e autenticare
tutti i claim ricorsivi, le relazioni ring e i norm check: una nuova PCS
blind/2PC, esattamente il lavoro che Akita lascia aperto.

La relazione one-hot con l'originale byte non è invece l'ostacolo:
`E_ij` booleani, `sum_j E_ij=1` e `A_i=sum_j j*E_ij` sono relazioni lineari
dopo la booleanità e danno anche il range byte. Serve però che l'apertura
privata di E termini nello stesso MAC di A. La PCS pubblica non lo fa.

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

**Wrapper ricorsivo Akita: screen minimo negativo.** In astratto si potrebbe
mettere prova, valutazione e transcript Akita nel witness di un blind GKR,
verificare `AkitaVerify` internamente e chiudere `y` sul MAC originale.
Questo rimuoverebbe la fuga pubblica, ma non è un adapter: aggiunge il
verifier lattice completo, aritmetica ring/range non nativa e la propria
PCS al circuito DV. Inoltre il Cor. 10.32 lascia meno di 64 bit dopo Q64
per una singola apertura da circa 128 bit; una composizione deve amplificare
anche quel termine prima di sommarlo agli errori B12.
Il toolkit lattice succinct del 2026/1289 offre ZK per relazioni lattice
native, ma non un adattatore black-box per il verifier Akita, il ponte Fp3
o l'endpoint VOLE-MAC; non cambia quindi questo esito.

Il costo sorgente chiude il port letterale prima del wrapper. Per il gruppo
canonico maggiore, il one-hot byte ha `256*2^34=2^42` bit; sui gruppi reali
O=150 sono 6.180.457.938.944 bit, circa 180 volte il massimo `2^35` della
Tab. 9. Akita risparmia sugli zeri nel **commitment**, mentre l'apertura ha
lavoro lineare nella lunghezza del polinomio. Il massimo pubblicato impiega
18,6 s per la sola apertura CPU; non si estrapola quel tempo a H100, ma la
scala e il nuovo wrapper impediscono un upper <=50 s. Shardare il one-hot
Fp entro arena richiede almeno 5.462 PCS e almeno 334,82 MB usando persino
61,3 KB per shard. Occorre quindi un'unica apertura sparse/virtuale con
reader streaming e prova privata; nessun componente corrente la realizza.

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

Il conto specializzato del paper per K=256,d=1 è `4T+O(K log K)` prodotti,
ossia 96.569.655.296 al caso O=150; la tabella precedente conserva il
termine generale prudente `6T=144.854.482.944`. Anche il minore richiede
6,44 miliardi di prodotti/s per occupare da solo 15 s, prima di PCS,
wrapper privato, producer, replay e serializzazione. Non esiste una misura
H100 equivalente da cui dedurre il tempo completo.

Il range W può essere provato una sola volta nello stesso key epoch e
registrato contro la stessa `C_W`; non deve essere riemesso nei turni 2–3.
Questo risparmierebbe 1.651.252 byte successivi, ma non rende gratuito il
prover iniziale. Un LogUp con inversi virtuali sostituisce l'albero da
3,30 TB con un product-sumcheck e una PCS aggiuntiva; il tradeoff a radice
quadrata sta nell'arena ma visita lo stream circa sei volte. Il nuovo
steering ammette quel numero, con tempo da verificare; l'attuale PCS densa
rimane fuori arena. Spostarlo all'installazione richiede una singola PCS
streaming e contabilizzazione di setup/tempo; è un successore analitico,
non una candidata ammessa.

**Premessa acquisita:** il proprietario ha autorizzato EA-LPN-SL-reg*
sulla geometria large-field e al bound proposto. Il port nativo resta
subordinato a una composizione fisicamente praticabile. Sul lato Shout serve invece una singola PCS
sparse/streaming privata che termini nei MAC originali e rispetti arena,
50 s, con letture interamente contabilizzate; nessun componente censito la realizza. Il vecchio
PCG B7, il refill con righe già consumate o un setup dipendente da Δ
classificato globale non sono sostituzioni ammesse.

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

### Guard dei cammini prima delle correzioni cGGM

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

La Fig. 2 consente al receiver corrotto di scegliere beta=0. Nella variante
rilassata onesta con t=1120 la probabilità di almeno uno zero è
`1-(1-1/p)^t`, circa **2^-53,87**: non si può assorbire fra gli errori da
78 bit. La successiva ottimizzazione large-field usa invece beta onesti
nonzero, ma un receiver corrotto può ancora dichiarare zero. Il precheck
precedente beta*eta=1 avrebbe consumato t righe aggiuntive. È sostituito
dal seguente guard, che copre entrambi i profili.

Per ogni blocco i e livello j, dopo d e prima di qualsiasi c, definire
`gamma_ij=s_ij-d_ij` sui MAC originali del seed. Il verifier ne ricava
la key correggendo linearmente con il d pubblico; `gamma_ij-beta_i` usa
la stessa beta originale. Si sottopongono tutte le `t*h` triple
`(gamma, gamma-beta, 0)` a **un solo batch prodotti** già presente nel
[consumer nativo](../../rust/volta-pcs/src/c71_matrix/range.rs). Servono
una maschera Fp3 disgiunta, cioè tre righe base, e due scalari Fp3 di wire.
Tutti i d, gli ID delle righe e l'ordine globale non resettabile delle
triple sono legati al transcript prima di lambda. Nessun c viene inviato
prima dell'accettazione; un fallimento brucia e termina l'intero setup,
senza retry sotto la stessa Delta.

Usando i segni nativi `k=m+delta*x`, porre
`e_l=gamma_l*(gamma_l-beta_block(l))` ed
`E(lambda)=sum_l lambda^l*e_l`. Il batch invia

```text
A = rho   + sum_l lambda^l * (gamma_l*m_(gamma-beta)_l
                              +(gamma_l-beta_l)*m_gamma_l)
B = m_rho + sum_l lambda^l * m_gamma_l*m_(gamma-beta)_l
B+delta*A == k_rho + sum_l lambda^l*k_gamma_l*k_(gamma-beta)_l.
```

La differenza è `delta^2*E(lambda)` per il wire onesto; un wire alterato
aggiunge soltanto termini di grado <=1 in delta. Se una relazione è falsa,
Schwartz–Zippel e il bound di radici danno nel modello MAC ideale

```text
epsilon_path <= (t*h-1)/|Fp3| + 2/|Fp3| = (t*h+1)/|Fp3|.
```

Per la variante large-field corrente `t=675,h=19` sono **178,353216 bit**;
persino moltiplicare meccanicamente per Q*=2^74 lascia 104,353216 bit.
Questo è il termine
del guard, non un bound composto B11→Dory. La maschera rende A uniforme;
condizionatamente allo stato del verifier, l'equazione determina B.

Fuori dall'errore, se beta!=0 si estrae
`r_j=gamma_j/beta in {0,1}` a **ogni livello**. Sono quindi esclusi prima
di c sia il cammino finale a due foglie sia il recupero con sigma scalare.
Se beta=0, tutte le gamma sono zero: `d_j=s_j`, `K(beta)=M(beta)` e
`K(r_j)=-M(s_j)`. Il simulatore sceglie c_0 uniforme, pone
`k=c_0+M(s_0)`, espande H in avanti e calcola ogni
`c_j=-M(s_j)+sum_left_j`. Simula esattamente l'intero c senza Delta,
divisione o cammino estratto. L'onesto soddisfa sempre il guard perché
`gamma=r*beta`; la distribuzione originale non viene condizionata.

Il [controllo finito](../../tests/test_c71_dory_path_guard.py) enumera
beta, s,d, lambda e Delta su F5; verifica estrazione, ramo zero, identità
MAC e gradi. È stato riesaminato indipendentemente senza trovare un
controesempio al lemma condizionale. Non copre adattività, FS, backend
Fp6 o una prova UC completa.

**Costo sostitutivo large-field.** La §4.2 della fonte permette, per
`F!=F2`, rumore regolare con payload onesto `beta in F*`: il receiver
corregge il seed uniforme con `delta=s_0-beta`. Table 2 misura però il
caso rilassato binario e non trasferisce i suoi 128 bit a Goldilocks.
La prima geometria `t=560,ell=9` è quindi sostituita dallo screen più
prudente **`t=675,h=19,ell=11`**, con `N=353.894.400=5*70.778.880`.
Resta un'istanza esplicita senza credito della nuova ipotesi
`EA-LPN-SL-reg*(675,70778880,353894400,11,Fp)`.

Il motivo del cambio è verificabile tramite i caratteri additivi. Per un
codeword nonzero con frazione `f_i` di coordinate nonzero nel blocco i,
il rumore regolare nonzero ha bias esatto
`prod_i(1-p*f_i/(p-1))`; il rilassato uniforme su Fp dà
`prod_i(1-f_i)`. Su Goldilocks sono quasi uguali, quindi il dimezzamento
binario di t non è una riduzione concreta. Applicando soltanto come screen
la regressione di distanza della fonte per ell=11, il profilo nuovo dà
**83,4181 bit** di bias, contro circa 70,46 per t=560/ell=11. La regressione
è empirica, non copre failure, ricerca del codeword o leakage statico:
non è il bound di advantage richiesto a T121/M93.
Ogni beta onesto va campionato esattamente in Fp*: un retry locale su
codifica canonica è indipendente dal valore finale. Un singolo campione Fp
seguito da abort avrebbe probabilità cumulativa circa `675/p`, troppo alta.

Con i check per blocco, il guard richiede `s=t*(h+4)+3` righe seed:
nessuna riga inversa. La correzione beta aggiunge `8*t` byte ricevuti;
i payload d,z restano `8*t*(h+3)`, c `24*t*h`, più 48 byte del guard.
Per il seed Fp6 della sezione seguente:

| Voce | Byte o righe |
|---|---:|
| Seed base Dory | 15.528 righe |
| Seed Fp6 Dory | 48.593.849 byte |
| Seed e payload Dory, traffico totale | **49.025.897 byte** |
| F_Rand ROM, framing incluso | **146 byte** |
| Parziale con coin | **49.026.043 byte** |
| Margine parziale su 130 MB | **80.973.957 byte** |
| Lower ricevuto | 47.826.264 byte |
| Lower ricevuto con PCS/altro corpo B12 conservato | **70.457.316 byte** |

Sommando prudenzialmente l'intero upper corrente del primo corpo B12,
65.053.244 byte, e i 146 byte della coin descritta sotto, il parziale
diventa **114.079.287 byte** e lascia **15.920.713 byte** per F_EQ e le
altre voci mancanti. È un upper del corpo più un parziale bootstrap, non
un upper completo.

Il check split vale 145,601259 bit e il suo enumeratore canonico conta
185.542.587.187.200 posizioni. Un fattore FS meccanico `2^74` lascerebbe
soltanto 71,601259 bit: questa candidata richiede coin interattive fresche
da F_Rand oppure una riduzione FS più stretta; lo screen non accredita FS.

Completamento, metadata e corpo restano fuori dal sottototale seed/payload.
Il guard scarica i due difetti di cammino identificati e
conserva la distribuzione rilassata; non realizza EA-LPN-SL o il cGGM.
Arena, legame agli originali e tempo completo restano obblighi aperti.

#### cGGM con random oracle separato per nodo

**Candidata condizionale che chiude il difetto RPM senza permutazione.**
Dopo l'accettazione del guard, usare

```text
H_D(x) = Fp3-Reject(SHAKE256(
  "VOLTA-C71-DORY-CGGM-v1" || setup_nonce || block || level || position || enc(x)))
```

dove `D=(setup_nonce,block,level,position)`, `enc` è il codec canonico Fp3
e il rejection sampler produce tre limb Fp uniformi. Il nonce è fresco per
l'unico setup e tutti i campi hanno lunghezza canonica. Fig. 3 resta
invariata: figlio sinistro `H_D(x)`, destro `x-H_D(x)`. Non esiste
un'interfaccia inversa. La separazione per posizione assegna una cella ROM
distinta a ogni nodo, anche se due valori Fp3 coincidono.

Per un receiver corrotto e un blocco con `beta!=0`, sia `z_j` il fratello
rivelato e `w_j` la somma dei fratelli precedenti della fonte. Il nodo
nascosto è

```text
u_j = K(beta)-w_j = M(beta)-beta*Delta-w_j.
```

Una query `H_D(x)` nella sola etichetta del nodo determina quindi il
candidato

```text
Delta' = (M(beta)-w_j-x)/beta.
```

Il simulatore lo inoltra alla global-key query ideale prima di rispondere.
Se ha successo, programma `H_D(x)=x-z_j` quando il bit del cammino è zero,
oppure `H_D(x)=z_j` quando è uno. Sono esattamente le due equazioni
`right=x-H_D(x)` e `left=H_D(x)`. Se la query non individua Delta, la
risposta rimane uniforme. Query nuove dopo `c` sono dunque simulate
esattamente.

Il vettore `c` va costruito internamente per livelli prima di consegnarlo:
`u_j` dipende soltanto dalle correzioni precedenti. Per le query già
registrate nel dominio del livello, il simulatore prova i candidati Delta.
Se trova quello corretto, usa l'output ROM già fissato per determinare il
fratello e quindi `c_j`; altrimenti campiona `c_j` uniforme. È la stessa
lazy sampling della vista reale, dove l'unico `H_D(u_j)` ancora fresco
rende uniforme la correzione. Un ibrido più semplice che dichiara bad su
una prequery conserva il seguente bound prudente nell'accounting:

```text
epsilon_ROM <= Q_ROM / |Fp3|.
```

Non compare un fattore `t*h`: ogni query porta già una sola etichetta
`block/level/position`; un union bound conta le query globali una volta.
Con `Q_ROM<=2^74` il termine ha **117,999999999 bit**. Nel ramo `beta=0`
il guard impone `d=s`, quindi `K(beta)=M(beta)` e `K(r_j)=-M(s_j)`; il
simulatore sceglie `c_0`, ricostruisce le due radici e tutti i `sum_0`
con sole query forward, ottenendo la distribuzione reale senza Delta.
Un input F_EQ malformato che accetta senza una precedente guess riuscita
aggiunge al più `1/(|Fp3|-Q_ROM)`. È censito separatamente nello screen.

Il Lemma 2 della fonte contro il sender corrotto non usa la forma RPM:
usa l'invariante additivo, il check universale e EA-LPN-SL. L'invariante
vale per ogni funzione `H_D`. Il trasferimento composto non è però ancora
automatico: deve includere il transcript mascherato del guard, gli abort
selettivi, le maschere split distinte e la semantica locale delle query
ROM. La sostituzione chiude quindi condizionatamente la sola parte cGGM
del Lemma 3 contro il receiver. Condizionatamente agli errori già censiti,
prima della seconda chiave F_EQ la somma seed/guard/split/ROM resta a
**90,9339 bit**; con entrambi i seed scende a **89,9339 bit**.

Il [controllo finito](../../tests/test_c71_dory_rom_cggm.py) verifica
estrazione, programmazione dei due bit, simulazione `beta=0` e la biiezione
Delta→nodo nascosto su F5. Non è una prova UC o un'implementazione SHAKE.
Restano da realizzare codec, rejection sampler e schedule nativa, da
formalizzare la composizione sender con guard/split sotto EA-LPN-SL
autorizzata e da chiudere framing, tempo e accounting completo.

#### F_Rand condizionale e F_EQ con due chiavi MAC

Dory tratta entrambe come funzionalità ideali. La fonte citata in precedenza
per F_EQ, [Liu et al. 2025](../../sota/2025-0614-one-bit-advantage-2pc.md),
dimostra il proprio 2PC nell'ibrido `(F_Com,F_OT,F_OLE,F_Rand,F_EQ)` e
quindi non le realizza. La verifica seguente non importa quel teorema.

Per F_Rand tutti i campi del commitment hanno codec canonico e lunghezza
fissa: `H("VOLTA-C71-DORY-COIN-v1" || setup_nonce || prefix_hash ||
direzione || messaggio || blind)`. Il prover
campiona `s1,blind1`, invia il commitment; il verifier invia `s0`; il prover
apre e il seed congiunto è `s0 XOR s1`. Da questo solo seed, dopo `d` e prima
dei check split, si derivano tutte le U_i con SHAKE256 e rejection sampling
canonico in Fp3. **Tutti i c devono essere inviati insieme a s0 prima
dell'apertura**: altrimenti il sender potrebbe adattarli alle U_i. Non sono
ammessi retry dell'intero setup. Ogni limb Fp ha
al massimo otto tentativi; il fallimento termina la sessione e contribuisce

```text
epsilon_sample <= 3*N*((2^64-p)/2^64)^8 < 2^-226.
```

Nel ROM programmabile, con al più `Q_ROM=2^74` query globali, l'envelope
prudente per commitment, blind, opening e prequery del seed XOF è

```text
epsilon_coin <= Q_ROM*(Q_ROM-1)/2^257
                + 3*Q_ROM/2^256 + 1/2^256 < 2^-108.
```

Contro il prover corrotto, un'apertura valida estrae `s1` dalla query che ha
prodotto il digest; se la query manca resta soltanto la guess. Contro il
verifier corrotto, il simulatore equivoca la coin dopo `s0,c`; una query
anteriore al seed XOF è inclusa nell'envelope. Il blind rende `s1`
indipendente prima della risposta. Il prover può comunque vedere la risposta
e poi abortire: questa è una realizzazione **con abort**. Poiché
abort brucia nonce, righe e sessione prima di qualsiasi output PCG, non crea
retry adattivi; il trasferimento dal F_Rand ideale di Dory deve però
esplicitare questa semantica. Non si accredita fairness impossibile a due
parti né una composizione UC dal solo argomento ROM.

Il wire completo è `32+32+64=128` byte; tre header da sei byte portano
F_Rand a **146 byte nelle due direzioni**. Il parziale bootstrap sale così a
**49.026.043 byte**; insieme all'upper corrente del primo corpo arriva a
**114.079.287 byte**, con **15.920.713 byte** residui sul cap iniziale.
Prima del secondo seed F_EQ, la somma degli errori condizionali noti resta
dominata dal seed Fp6 a circa **90,93 bit**.

La candidata che invia `w in Fp3^675` resta **respinta**: sul mismatch un
verifier corrotto apprende l'intero vettore dei residui, non il solo AND
concesso dal leakage EA-LPN-SL. Il formato scartato avrebbe 26.962 byte.
Anche comprimere prima i vettori con una sfida pubblica non basta: senza
una prova che lega il fingerprint al vettore precedente, una parte corrotta
può scegliere soltanto lo scalare. La variante OLE a una riga confronta un
solo elemento di K; 675 istanze rivelano gli esiti singoli e il solo seed
B11 supera 130 MB. Nessuna di queste varianti riceve credito.

Anche il confronto dei soli digest ROM è **respinto**. Se P0 malforma un
solo blocco, può enumerare i `2^19` cammini, calcolare ogni possibile input
onesto `w` e confrontarne il digest con quello ricevuto. La min-entropia
condizionale è al più 19 bit, non `log2|K|`; a `Q_ROM=2^74` la prequery ha
probabilità essenzialmente uno. Le maschere sono già assorbite nel valore
`v` noto a P0. Il formato da 153 byte conserva binding e correttezza, ma
non il leakage di un solo bit e non riceve credito.

**Due esclusioni malevole.** La PEQT a doppia esponenziazione di
[Cong et al. 2024](../../sota/2024-1340-unbalanced-psu-private-equality.md)
è provata soltanto semi-honest. L'estensione P-521 con PoK Schnorr e DLEQ
richiede di estrarre il primo esponente: il forking generico trasforma
un vantaggio `epsilon` in circa `epsilon^2/Q_ROM`. Con
`Adv_DLog<=2^-193` e `Q_ROM=2^74` restano circa 59,5 bit, sotto 78.
Il precedente wire da 823 byte e il suo envelope DDH non ricevono credito.

Neppure il malicious PSI di
[Rosulek--Trieu 2021](../../sota/2021-1159-compact-malicious-psi-small-sets.md)
è una F_EQ letterale. Per `n=1` il polinomio è costante e il protocollo
aborta; con `n=2` e un dummy si ottiene un output PSI a una sola parte e
la funzionalità ammette slack nell'insieme estratto. Duplicare le direzioni
per consegnare il bit a entrambi permette a una parte corrotta di scegliere
due input diversi. Il core evita il forking, ma non soddisfa l'interfaccia.

**Candidata F_EQ con due chiavi MAC, senza nuova ipotesi gruppo.** Il seed
Dory corrente fissa `Delta0` e viene esteso di `3*t` righe base. Un secondo
seed Fp6 fresco di `3*t` righe, coi ruoli scambiati, fissa `Delta1`.
Entrambi i setup completano e sono sigillati prima di qualsiasi input.
Usando la convenzione bootstrap `m=k+Delta*x`, le parti autenticano ogni
coordinata dei due vettori `v,w in K^t` sotto la chiave della parte opposta:
tre righe Fp per un elemento Fp3. Le correzioni chosen-input `d=x-r`
sono uniformemente mascherate e vengono fissate in un frame per ruolo.

Soltanto dopo entrambe le correzioni una seconda F_Rand genera coefficienti
freschi `r_i in K`; si comprimono valori, tag e key in `vbar,wbar`. Se
`m_w=k_w+Delta0*wbar` e `m_v=k_v+Delta1*vbar`, le share sono

```text
s0 = -k_w - Delta0*vbar - m_v
s1 =  m_w + Delta1*wbar + k_v
s0+s1 = (Delta0+Delta1)*(wbar-vbar).
```

Ogni parte committa
`H(D_com||SID||role_i||s_i||blind_i)`; entrambi i commitment precedono
le aperture. Si accetta soltanto se la somma aperta è zero. Sul mismatch
fissato, la compressione è zero con probabilità `1/|K|`; altrimenti la
chiave onesta di B11 è uniforme in `K*`. Per un residuo compresso nonzero D,
la somma è uniforme su `K` tranne il punto `Delta_corrupt*D`; la cancellazione
costa al più `1/(|K|-1)`. Lo stesso bound copre qualunque share malevola
fissata prima dell’apertura onesta, per il massimo peso di un punto nella
distribuzione della share onesta; non si somma un secondo errore di forgery.
Condizionando sul rifiuto, le distribuzioni di due
residui hanno distanza statistica al più `1/(|K|-2)`: questo termine realizza
il leakage di un solo bit senza consentire il dizionario dei cammini. Una
share malevola deve essere fissata prima di vedere quella onesta. Un guess
della chiave onesta nelle global-key query aggiunge `Q_ROM/(|K|-1)`.
Withholding o codec non canonico causano abort e burn di entrambi i setup.

Questo realizza F_EQ con abort nel modello ROM e dei due seed MAC, senza
one-more gap CDH, VOPRF o DLEQ. Il secondo seed aggiunge un'altra copia del
bound Fp6: la somma condizionale nota passa a **89,9339 bit**. Restano
obblighi nativi il roleswap B11/Fp6, il codec delle correzioni e l'ordine
atomico setup→input→coin→commit→open.

Per `t=675`, il seed principale cresce di 2.025 righe e quello inverso ne
usa 2.025: **12.782.489 byte**. Le correzioni chosen-input costano 32.412
byte, la seconda coin 146 e commit/open 200. F_EQ costa quindi
**12.815.247 byte**. Il bootstrap candidato completo delle primitive
censite è **61.841.290 byte**; con l'upper corrente del primo corpo arriva
a **126.894.534 byte**, lasciando **3.105.466 byte**. Resta `credit:false`
per composizione, schedule/tempo e implementazione; EA-LPN-SL-reg* è
ora assunta con il bound autorizzato, F_EQ ha l’argomento ibrido sopra.

**Composizione sender condizionale.** Contro P0 corrotto, l'honesto P1
soddisfa sempre il guard. La sua share `A=rho+known` è uniforme e `B` è
determinata dall'equazione MAC, quindi accettazione o abort del guard non
aggiunge una predicate sul rumore. P0 fissa tutto `c` insieme alla risposta
della prima coin prima dell'apertura. Le U_i fresche producono le fibre
cartesiane della Def. 2 fuori dall'evento split; il rappresentante canonico
per blocco preserva key e accumuli nell'Hybrid 2→3 della fonte. La F_EQ MAC
espone un solo AND finale e il withholding diventa abort dell'intero setup.
Il lavoro del riduttore `t*B^2=185.542.587.187.200` è circa 2^47,4 e si può
enumerare in streaming, entro T121/M93. Contro P1 corrotto, il guard estrae
i cammini binari e il cGGM forward-ROM realizza il ramo receiver già
descritto. Tutti gli epoch vengono bruciati su qualunque fallimento.

Per un'unica leakage cartesiana, senza moltiplicare l'EA game per Q*, il
bound candidato ha la forma

```text
Adv_boot <= Adv_EA-LPN-SL-reg*(675,70778880,353894400,11,Fp;
                               T=2^121,M=2^93,one-leakage)
            + epsilon_seed/guard/split/ROM/coin/F_EQ.
```

Il secondo termine vale meno di 2^-89,9339. Il proprietario ha ora
**autorizzato** `Adv_EA-LPN-SL-reg* <= 2^-80` alle risorse e alla geometria
sopra: il ledger bootstrap condizionale supera quindi 79,99 bit. La
regressione da 83,42 bit resta uno screen, non una dimostrazione della
premessa. B12 v1 conserva il suo teorema; il goal usa il trust model
esteso dichiarato nel design, con gli obblighi compositivi ancora aperti.

Le fonti PEQT, PSI e OPRF sono state acquisite il 2026-09-12 senza
sovrascritture. SHA-256 PDF/Markdown: PEQT
`18a5340fc7dfb2fdab83026cf34cfd88b5ee63bd3d3d42d01aeb2b93e038e413` /
`a721d8dc8e817861a6f5c72056bb489a7315a37cb1670aff6ae0440d594ac913`;
PSI `91477d8a5c838b023d48f11f3f508c43a66a483b6b97aed01a1109eebd8cdfe7` /
`81852098d1029e7645b99fb32dd2a0a9748c244e60f96d1016870fd4074c8c1b`;
OPRF `316f4634a0dcbc041598bf4589682ae53ce74417ec18e72cbcc87f4cc53664a9` /
`eb51613320d152cf2a06a87ab04b3208fe7f566555bbf19a8cca64cdce10801f`.

### Seed Fp6: compressione a 95 bit nel singolo setup

**Nuova candidata analitica: ridurre il campo interno del seed, mantenendo
Fp/Fp3 all'uscita.** La [fonte Wolverine](https://eprint.iacr.org/2020/925),
Fig. 5/Teorema 2 e Appendice B.2 nel
[Markdown conservato](../../sota/2020-0925-wolverine.md), specifica
`ell=ceil(2*rho/log2(p^3))+1`. B11 sceglie rho=128 e quindi ell=3,
campo interno Fp9. Con un solo setup fresco e target completo >=78 bit
si può valutare **rho=95, ell=2, campo interno Fp6**. Non si abbassano
le ipotesi AES-256/P-521 o le risorse avversarie T80/M80/Q64.

Il bordo va calcolato esattamente: `2^190 < p^3 < 2^192`.
Rho=95 ammette ell=2; **rho=96 richiede ancora ell=3**, perché p è
minore di 2^64. Arrotondare log2(p³) a 192 darebbe un parametro errato.
Il campo candidato è `K6=E[v]/(v²-7)`, con `E=Fp[u]/(u³-2)` già usato.
Il controllo `7^((p-1)/2)=-1` e il grado dispari di E/Fp implicano che
7 non è un quadrato in E. La base Fp è `1,u,u²,v,uv,u²v`.

Si eseguono **384 OT** e il check nell'intero K6, con sei righe maschera
indipendenti e challenge K6 dopo tutte le correzioni COPE. Solo dopo il
check si campionano alpha0,alpha1 in E e si applica
`C_alpha(x0+v*x1)=alpha0*x0+alpha1*x1` a Delta, key e tag. La mappa è
E-lineare e universale, e conserva `M=K+Delta*x` per il plaintext x in
Fp. La rimozione del leakage usa lo stesso teorema Wolverine; non è il
taglio arbitrario di tre limb. La simulazione del check contro verifier
malevolo usa tutte le sei maschere. La key compressa zero termina il setup,
con l'evento ideale 1/p³ già addebitato.

**Bound condizionale della sola componente seed.** Il
[diagnostico](../../scripts/c7_1_gemma_plan.py) `c71_fp6_seed_screen`
conserva per prudenza tutti gli envelope B12 a 576 OT, profondità 24,
T121/M93/Q*=2^74 e una sola installazione. Il nuovo numero di OT, le
righe sacrificate, i sampler e l'aritmetica schoolbook non li aumentano.
Sostituisce soltanto il termine statistico:

```text
epsilon_seed6 = epsilon_B12_seed - 2^-128 + 2^-95
              < 2^-90   (90,9339079333 bit).
```

Resta compreso l'upper conservativo `(192²+1)/p³` del check e della key
zero. Il termine bootstrap entra una volta, senza un ulteriore fattore
Q*; è così che viene composto nel contratto B12 corrente. Il conto non
copre un lifetime di 2^20 setup, Dory, EA-LPN o l'intero certificato.
Non cambia il teorema B12 selezionato o il suo backend Fp9.

**Wire candidato, stesso formato dimensionale e nuovo dominio/suite da
implementare.** Per n righe base restituite, contando anche le sei sacrificate:

| Voce, due direzioni | Byte |
|---|---:|
| 384 OT, quattro punti P-521 e due ciphertext seed ciascuno | 127.488 |
| COPE | 3.072*(n+6) |
| Challenge K6 esplicite | 48*n |
| Contesto/nonce/frame, risposta del check e compressione | 529 |
| Seal del seed | 40 |
| Totale del seed | **146.489+3.120*n** |

Con le **15.528 righe** del profilo large-field, del guard e dei check per
blocco, il seed costa 48.593.849 byte. Aggiungendo correzioni e payload
Dory già censiti si arriva a **49.025.897 byte di traffico totale**, con
80.974.103 byte di margine parziale sul primo tetto. Il lower ricevuto è 47.826.264 byte,
esclusi sacrifici/OT e altre voci. Il risparmio sul sottototale Fp9 con
precheck dell'inverso è **80.794.256 byte**. F_Rand/F_EQ, completamento Dory, metadata e
corpo vanno ancora aggiunti; il margine non è un upper del certificato.
Conservando il lower di PCS e altro corpo B12 dopo la rimozione dei soli
P/S si arriva a 70.457.316 byte: restano 59.542.684 byte, ancora non
assegnabili finché le voci mancanti e l'upper del nuovo corpo non sono chiusi.

Il [test locale](../../tests/test_c71_fp6_seed_screen.py) controlla il
bordo 95/96, il nonsquare, la compressione dei MAC originali, i byte e
la sostituzione esatta del termine di errore. Non esegue OT/AES o un
codec Fp6. La candidata richiede una suite distinta, mapping nativo e
test malevoli prima del riuso; **non si cambia il parametro in B11 sul
posto**. Il prossimo obbligo crittografico dell'espansione resta il cGGM
con il guard accettato, senza sigma scalare vulnerabile. Non sono
ancora chiusi il trasferimento sotto la premessa LPN autorizzata, l’arena
o il costo completo entro 50 s.

## Screen dopo l'autorizzazione EA-LPN e ripiego sui byte

Il [nuovo diagnostico](../../scripts/c71_streaming_screen.py) usa le geometrie
e gli intervalli B12, senza importare le modifiche RNE sperimentali. Il trust
model autorizzato è B12 + EA-LPN-SL-reg*. La capacità Dory di 70.778.880
righe **base** supera le 11.466.948 dell'intero run canonico: tre righe base
per Fp3, setup unico, nessun bootstrap aggiunto ai turni 2–3. La F_EQ
consuma i suoi due seed separati già contati, non questa capacità espansa.

La somma conservativa `epsilon_B12 + 2^-80 + epsilon_boot_known`, senza
nemmeno sottrarre il vecchio errore bootstrap B12, dà 79,8211 bit di
soundness e 79,9978 bit di ZK. È un ledger condizionale alla realizzazione
della medesima interfaccia MAC e alla composizione; non prova il refinement
del nuovo bootstrap o di una PCS modificata. Si arrotondano gli errori
razionali verso l'alto a 256 bit nel rapporto, senza accreditarli al runtime.

| O | Lower corpo B12 | Upper corpo B12 | Con bootstrap censito al solo primo turno |
|---:|---:|---:|---:|
| 0 | 47.841.180 | 65.053.244 | 109.682.470–126.894.534 |
| 150 | 54.868.318 | 78.945.726 | 54.868.318–78.945.726 |
| 300 | 61.797.384 | 92.723.304 | 61.797.384–92.723.304 |

Il proprietario consente i lower come **esito analitico della parte
proof-size**, se non si trova una soluzione praticabile da 40 MB. Le
alternative sotto 40 MB censite restano respinte fisicamente: si registra
questo ripiego autorizzato. Restano distinti upper, prove valide prodotte
e fallback: i lower omettono GKR congiunti e fratelli Merkle, e la prima
somma omette ancora il framing esterno/completion non censito del bootstrap.
Il goal completo non si chiude con questa sola tabella.

**RS per coset: identità corretta, replay da integrare.** Nel commitment
[CFW corrente](../../rust/third_party/p3-whir-c61/src/pcs/zk/committer.rs)
una colonna è la DFT di messaggio, pad e zeri; il Merkle impegna righe
complete. Per produrre un coset `z*<omega>` lungo L, basta ridurre i
coefficienti modulo `X^L-z^L` e calcolare una DFT di L elementi. Il
[controllo finito](../../tests/test_c71_streaming_screen.py) confronta
tutte le posizioni con la valutazione diretta, pad compreso, su F97.

Consideriamo la costruzione concreta che mantiene buffer di coset a
**larghezza completa**, ricostruisce ciascun batch con una scansione della
sorgente e li scarta dopo l'emissione. Se un batch produce R righe di
larghezza b, occupa almeno `8*b*R` byte; con arena S, il numero di scansioni
necessarie è almeno `ceil(H/floor(S/(8*b)))`. Questo ammette ottimisticamente
qualunque numero di coset per batch e nessun altro buffer.

| Primo oracolo B12 | H × b | Codeword | Scansioni sorgente minime in questa costruzione | Buffer minimo per quattro scansioni |
|---|---:|---:|---:|---:|
| W/D35 | 2^32 × 128 | 4.398.046.511.104 B | 683 | 1.099.511.627.776 B |
| A/D34 | 2^31 × 128 | 2.199.023.255.552 B | 342 | 549.755.813.888 B |

Sono esclusi workspace FFT, pad, riordino delle righe per hashing,
Merkle/frontiere e rigenerazione per le aperture successive. Una scansione
di W qui legge l'intera sorgente packed; padding pubblico non aggiunge
letture ma non riduce le visite a W. La variante per colonne evita alcuni
replay conservando gli stati intermedi di tutte le righe: persino
ipotizzare 32 byte per riga richiede 137,44 GB per W e 68,72 GB per A.
Non è un lower universale sulle FFT o sulle PCS: respinge questi due
adattamenti specifici del layout corrente.

**Sumcheck lineare in due passaggi: il costo delle forme non sparisce.**
Per `L(i,j)=sum_a u_a(i)*v_a(j)` il primo passaggio calcola
`A_a(i)=sum_j W(i,j)*v_a(j)`. I primi k round del sumcheck quadratico si
calcolano piegando A_a e u_a; dopo r_prefix, il secondo passaggio calcola
`B(j)=sum_i eq(r_prefix,i)*W(i,j)` e conclude i round sul suffisso. Il test
confronta coefficienti, sfide derivate dai messaggi e terminali col percorso
denso, su forme anche con selettori di prefisso. Sono identità algebriche,
non un codec MAC implementato; applicare le medesime maschere richiederebbe
ancora il trasferimento nativo e la disciplina NoPeek del caller.

La contrazione A_a deve però includere anche i per cui `u_a(i)=0`:
il folding introduce termini incrociati. Già `W(x,y)=x*(1-y)` e
`L(x,y)=(1-x)*(1-y)` danno primo messaggio `x-x^2`; troncare W al solo
supporto booleano di L produce invece zero e altera il protocollo. Quindi
la disgiunzione dei Cube originali non dimostra lavoro O(N). Quando i v_a
hanno supporto pieno sul suffisso, questo algoritmo contrae ogni cella
per ogni forma, pagando rank×N. Ha due letture ma non supera il contratto
sul lavoro delle sorgenti. Questo respinge il port letterale prefix-first,
non ogni ordine dei round.

**Variante suffix-first: due letture e array W compatibili, PCS ancora aperta.**
Si scrive l'indice originale come `(i,j)`, con 20 bit di prefisso e 15 di
suffisso. Il primo passaggio calcola `C_a(j)=sum_i W(i,j)*u_a(i)` e i primi
15 round piegano C_a e v_a. I selettori di prefisso rimangono fissi durante
la contrazione: si possono fondere le visite degli intervalli in una sola
lettura, senza troncare le j fuori dal supporto di v_a. Dopo r_suffix,
il secondo passaggio calcola `B(i)=sum_j eq(r_suffix,j)*W(i,j)` e conclude
i 20 round con `L(i,r_suffix)`. I v_a pubblici sono rigenerati per termine,
C si piega in-place; non occorre conservare una seconda matrice rank×2^15.

Il [censimento riproducibile](../../scripts/c71_streaming_screen.py) usa
metadati pinned, gli helper delle forme W e token pubblici 0..149:
773 forme P0, 3.606 Cube P0, uno range pieno e 15 di padding. Per questi
3.622 termini gli array C occupano **2.848.456.704 byte** e B/L
**50.331.648 byte**: persino la somma simultanea **2.898.788.352** entra
nell'arena, prima di metadata e buffer delle altre fasi. Il modello di
contrazione conta `sum_a 2^max(dim_a,15)` = **280.138.842.112** aggiornamenti
nel primo passaggio e **314.498.580.480** includendo il secondo. Questo
conteggio conserva interi Cube anche quando un fattore interno è booleano;
non presume rank×N gratis, né include folding, range, PCS o hash.
È un upper uniforme sulle sequenze ammesse di 150 token: l'embedding
`[262144,5376]` ha un solo tile lungo l'asse vocab e tre lungo i canali,
quindi ogni posizione contribuisce al massimo Cube di dimensione 30/28/26.
Ripetizioni o ID estremi non aumentano il numero; coefficienti pubblici
nulli possono soltanto ridurlo. I token 0..149 realizzano il massimo
nel diagnostico, senza imporre quel contenuto al run.

Il terminale passa alla PCS il punto **originale `(r_prefix,r_suffix)`**,
benché le sfide arrivino nell'ordine inverso. Il controllo finito verifica
entrambe le valutazioni W e L su quel punto. L'oracolo impegnato e i MAC
originali restano gli stessi; non si introducono PCS per token o blocco.
I 35 round restano quadratici, con le medesime cardinalità wire/MAC.
Serve però un ordine pubblico distinto nel dominio del transcript e il
refinement della composizione blind/NoPeek: il test F97 non li dimostra.
Non si attribuisce quindi il teorema B12 v1 al nuovo programma.

È una candidata utile per il solo riduttore W. Il reader fisico packed,
le forme A/KV e il range non sono implementati da questo diagnostico;
il budget completo deve includerli. Encoding e apertura PCS aggiungono
letture W da prezzare; il nuovo steering rimuove il precedente tetto di quattro.
Mancano un upper di tempo e il confronto del lavoro totale su tutti i
prefissi. Nessuno di questi controlli ammette il prover completo.

## Schedule integrato: liveness, range e PCS privata

Il proprietario autorizza ora esplicitamente lo screen locale integrato
suffix-first + range + PCS privata, con arena 6 GiB e 50 s invariati.
Dal 2026-09-13 quattro letture W sono un obiettivo di ottimizzazione,
non un cap: il checkpoint viene rivalutato sul calcolo e sul traffico. Il [diagnostico](../../scripts/c71_streaming_screen.py)
separa occupazione simultanea, riuso temporale e dipendenze dalle sfide.

**Memoria disponibile.** Sottrarre 2.898.788.352 dall'arena dà esattamente
**3.543.662.592 byte**: gli array censiti occupano il 44,995% dell'arena.
È il margine prima di altri buffer/stati vivi, non una riserva già assegnata
a una PCS. I 6 GiB sono un requisito progettuale distinto dal picco globale
di 80 GB. Con W packed e arena piena rimangono **12.162.858.496 byte** del
picco globale per gli altri residenti; KV/runtime non sono già dimostrati
compatibili da questa sottrazione. I temporanei dell'inferenza rientrano
anch'essi nell'arena, quando vivi.

Il vecchio conto C+B+L è prudente: dopo i primi 15 round basta conservare
il target MAC aggiornato; C non ha più consumer nel secondo passaggio.
Dopo l'ultimo consumer e completamento GPU, lo spazio si può riusare.

| Fase lineare | Array nominati vivi | Margine prima degli altri stati |
|---|---:|---:|
| Contrazione C e primi 15 round | 2.848.456.704 | 3.593.994.240 |
| Seconda lettura W e ultimi 20 round, B/L | 50.331.648 | 6.392.119.296 |
| Dopo il terminale MAC | B/L rilasciabili | Arena riutilizzabile dalla PCS, dedotti i suoi stati trattenuti e gli altri consumer |

La fase PCS viene dopo linear nel [caller corrente](../../rust/volta-pcs/src/c71_matrix.rs):
conservare solo il terminale non implica conservare gratuitamente il witness
di apertura. Il root iniziale precede già la prova; encoding iniziale,
pad/sali, eventuali dati retained e successiva apertura rimangono nel conto.

**Ordine e fusioni lecite.** [Security §3](security.md#3-schedule-completa-e-destinazione-degli-endpoint)
e `range.rs` fissano istogramma autenticato → alpha/rho → range W → range A
→ batch lambda → 35 round linear → PCS. Le C delle forme P0 possono essere
accumulate dopo P0, separatamente e senza lambda; quelle del padding solo
dopo rho. Entrambe possono condividere una scansione post-alpha del range.
La C della forma range piena dipende invece dal punto dell'ultimo livello
leaf. **Ogni livello GKR sostituisce il proprio punto**: il punto prodotto
dai livelli alti non anticipa le coordinate finali. La scansione B richiede
le prime 15 sfide linear; la PCS il punto completo successivo. Nessuna
fusione anticipa queste sfide o riusa MAC di un tentativo precedente.

Un istogramma numerico privato del W immutabile, con padding zero incluso,
può essere materiale globale: **65.535 contatori u64 = 524.280 byte**.
Si contabilizza la sua costruzione una volta, si autenticano ed emettono
nuove correzioni a ogni tentativo e soltanto dopo si estrae alpha. Questo
risparmia la lettura dell'istogramma per risposta, non la costruzione
post-alpha dell'albero. Non si memorizzano globalmente transcript o tag.

**Checkpoint range: spazio compatibile, replay da prezzare.** Il range W
letterale trattiene W convertito, tutto l'albero e figli/equality dell'ultimo
livello: `24N + 48(2N-1) + 60N = 180N-48`, cioè
**6.184.752.906.192 byte** a D35. Già questi buffer visibili superano l'arena.
Una variante streaming può invece costruire radici di blocchi da `2^k`
foglie con una pila O(k), conservando solo le M=`2^(35-k)` radici e antenati.
Il top tree usa `48(2M-1)` byte; il suo GKR corrente aggiunge `60M` per figli
ed equality. Il [test finito](../../tests/test_c71_streaming_screen.py)
confronta tutte le radici/antenati con l'albero completo, senza allocare W.

| Livelli bassi scartati k | Picco array del top GKR | Con C trattenuta | Esito memoria dei soli array |
|---:|---:|---:|---|
| 10 | 5.234.491.344 | 8.082.948.048 | Entra solo senza C |
| 11 | 2.617.245.648 | 5.465.702.352 | Entra anche con C; residuo 976.748.592 |

Sono payload degli array nominati: produzione di equality, riallocazioni,
metadata e staging hanno un budget distinto. Non sono upper del picco
del processo o misure del backend nativo.

Il checkpoint non prova i k livelli scartati. Nella costruzione letterale
che rigenera **un livello alla volta da W**, le sfide adattive impongono
almeno k nuove visite: con istogramma cached il solo range costa almeno
`1+k`, ossia **11/12 letture** nei due casi, prima dei replay interni ai
sumcheck. Aggiungendo separatamente le due scansioni linear e una per la
rimaterializzazione PCS si ottengono almeno **14/15**. Non è un lower su
ogni protocollo range, né un upper completo dei passaggi. Il numero
di letture non respinge più questa schedule sotto lo steering aggiornato.

Lo screen integrato conserva dunque il riuso dell'arena e la cache numerica
dell'istogramma e riapre il replay per livello sul costo completo.
Restano da costruire range ed encoding/apertura privata compatibili: il
replay RS a righe complete resta a 683 letture persino con arena intera.
Il trasferimento del range a un nuovo protocollo deve mantenere i target
originali e scaricare soundness/NoPeek. A/KV, PCG, staging, allocator e
lavoro su tutti i prefissi restano voci esplicite non prezzate. Tempo
completo e numero massimo di letture restano **ignoti**, non zero; nessuna
build canonica densa o misura GPU viene autorizzata dallo screen.

## Checkpoint range con piu letture autorizzate

Lo steering del 2026-09-13 mantiene arena, HBM, 50 s, privacy, endpoint e
trust model, ma rende quattro letture un obiettivo di ottimizzazione.
I precedenti 11/12 passaggi del solo range erano **lower**, non schedule
complete: mancavano i replay dentro i sumcheck. Non costituiscono più una
ragione di esclusione. Rimangono respinti i layout che materializzano TB.

**Schedule concreta, k=10, C differita.** Dopo alpha si costruiscono in una
visita le radici dei blocchi da 1.024 foglie e il top tree. Il top GKR usa
gli array già censiti da 5.234.491.344 byte; dopo il suo terminale il tree
è rilasciato completamente. Non si conserva C durante questa fase.
Nei dieci livelli bassi il numero di coordinate m va da 25 a 34:

1. Per i primi `g=max(0,m-25)` round, si enumera un bucket di suffisso per
   volta. Per ciascun bucket si ricostruiscono da W i figli per ogni
   assegnazione booleana del prefisso e si accumulano otto scalari
   (quattro child per ciascuno dei due valori della coordinata corrente).
   Una pila per i sottalberi e una visita DFS dei pesi del prefisso usano
   spazio O(d). Non si memorizza un'intera tabella di pesi del prefisso.
   Il coefficiente cubico viene emesso prima della nuova sfida.
2. Una visita successiva, con quelle g sfide ormai fissate, materializza
   i quattro child piegati, lunghi al massimo `2^25`, e l'equality pubblica.
   Il payload è **120*2^25 = 4.026.531.840 byte**. I round restanti procedono
   in-place; i valori dell'ultimo round bastano per il terminale dopo la
   sfida, senza un'altra visita W.
3. Si rilasciano i child alla fine del livello. Ogni livello usa un nuovo
   punto; il suo prefisso non anticipa il punto leaf finale. Dopo tutto il
   range W e A, le due scansioni suffix-first restano separate, seguite
   dalla PCS privata sul punto originale.

Il numero di visite per livello è `v_m=1+max(0,m-25)`: 1..10, **55 visite**,
più la costruzione iniziale = **56**. k=11 ne usa 57. Il replay senza
materializzazione intermedia ne userebbe 320 a k=11. I valori 59/60 che
aggiungono due linear e una ricostruzione PCS sono solo parziali: non
chiudono encoding iniziale, ulteriori replay PCS o producer A/KV.

Il [controllo minimo locale](../../tests/test_c71_streaming_screen.py)
confronta ogni coefficiente cubico e i terminali con i child densi, con
sfide dipendenti dai messaggi. Conta inoltre una visita a ogni foglia per
round ricostruito/materializzazione e `N-2^(m+1)` merge per visita. Non
esegue MAC, FS nativo, GPU o allocazioni canoniche. La correttezza generale
segue dalla linearità del folding dei singoli child prima del prodotto,
non dal prodotto delle valutazioni booleanamente troncate. Il refinement
del reader packed e della disciplina NoPeek resta da scaricare; i segni
dei MAC e i polinomi del range non vengono cambiati da questa schedule.

**Conti distinti per k=10.** Il [rapporto](../../scripts/c71_streaming_screen.py)
mantiene i seguenti conteggi di espressioni/visite, senza frequenze hardware:

| Voce | Quantità censita | Limite del conteggio |
|---|---:|---|
| Payload W letto, residente in HBM | 3.438.102.671.360 B | Gather nel layout virtuale; non transazioni HBM effettive |
| Trasferimenti esterni di W per queste visite | 0 | Condizionato a W residente; caricamento globale separato |
| Valutazioni foglia logiche, padding incluso | 1.924.145.348.608 | Il padding zero non legge W |
| Merge razionali, costruzione e replay | 1.305.602.949.119 | Ogni merge generico: 3 mul Fp3 e 1 add |
| Accumuli scalari dei child sui prefissi | 1.237.084.798.976 | Nel riferimento generico, 1 mul e 1 add ciascuno |
| Bucket coefficienti cubici, intero range | 34.359.738.332 | 27 mul e 23 add/sub Fp3 per bucket nel nucleo corrente |
| Fold residenti | Censiti separatamente nel rapporto | Ogni interpolazione: 1 mul e 2 add/sub |
| Scratch/child/equality in HBM | Da chiudere | Letture, scritture, allocator e generazione pesi non inclusi nel payload W |

I prodotti per coefficienti/merge non sono istruzioni GPU; moltiplicare
una componente base o una costante può costare meno del prodotto Fp3
generico. Non si sommano conteggi sovrapposti e non si usa il picco HBM
come throughput delle operazioni di campo. Il carico del checkpoint è
esplicito, non rivendicato come trattamento lineare uniforme delle sorgenti;
il confronto di lavoro totale su ogni prefisso resta aperto.

**Voci ignote e controlli minimi.** La somma per risposta resta
`T_inferenza + T_witness/range + T_PCS + T_PCG + T_serializzazione + T_IO_residuo`,
senza overlap presunto. L'IO dentro un kernel misurato non si aggiunge una
seconda volta al tempo dello stesso kernel.

| Componente | Controllo minimo necessario | Stato |
|---|---|---|
| Range: algebra e visite | Confronto finito adaptive gather/rebuild/retain contro il denso | Passato localmente |
| Range: memoria fisica e traffico | Reader su descrittori dyadic, trace di transazioni/staging e riserve; equality generata in buffer preallocato | Aperto, nessuna allocazione D35 autorizzata |
| Campo/range: tempo | Kernel del merge e del bucket sul campo effettivo, poi replay rappresentativo con gather; nessun riscalamento da CPU | Non misurato; hardware fuori da questa autorizzazione |
| PCS privata | Encoder e rigenerazione delle aperture/Merkle su un dominio piccolo con pad/sali originali, poi census completo di array, visite, FFT/hash | Aperto; 683 scansioni del replay RS sono soltanto un lower, ora non escludente da solo |
| PCG | Dory Fp6/guard/roleswap su parametri ridotti con codec e stato massimo vivo; census dell'espansione completa | Aperto; 61.841.290 B sono wire delle primitive, non tempo o memoria del PCG |
| Inferenza e witness A/KV | Liveness dei producer canonici con medesima semantica; leggere/riprodurre A senza spill o seconde cache | Aperto; il piccolo runner non misura il carico canonico |
| Serializzazione | Writer incrementale che conta il certificato e i buffer, inclusi completion e framing | Aperto; restano i bound analitici del corpo |
| Trasferimenti esterni residui | Timeline esplicita di caricamento globale, staging e protocollo; conteggio senza duplicazioni | Aperto; non si presume spill né banda effettiva |

La candidata checkpoint viene quindi **mantenuta per approfondimento
minimo**, non respinta per 56 visite e non ammessa sotto 50 s. Il goal
completo resta aperto: i costi ignoti hanno upper di ammissione infinito.
Nessuna nuova premessa crittografica, spesa o esecuzione pesante è introdotta.

## Range con finestre Gram private

**Candidata locale del 2026-09-13:** il replay da 56 visite è superato
nel modello aritmetico da una schedule a **26 visite W per il range**.
Non cambia il protocollo range: nessun nuovo oracolo, sfida, messaggio,
MAC o errore crittografico. Rimangono da dimostrare refinement del reader,
NoPeek nativo e risorse complete; `credit:false` resta obbligatorio.

Al livello con m coordinate dei child, dopo un prefisso r già sfidato,
si scrivano A=P_left, B=Q_left, C=P_right, D=Q_right e
`U=lambda*A+B`, `V=lambda*C`. Il prodotto da sommare è `U*D+V*B`.
Per una finestra di b coordinate, L=2^b, e suffisso t, accumulare privatamente

```
H[u,v] = sum_t eq(parent_tail,t) * (U(u,t)*D(v,t) + V(u,t)*B(v,t)).
```

Ogni bucket t ricostruisce da W i 4L child, contraendo soltanto il
prefisso già noto. Ogni foglia è visitata una volta per finestra.
H ha L² elementi Fp3: è generalmente **non simmetrica**. Per il round
corrente, i blocchi diagonali 2×2 contribuiscono i coefficienti quadratici
`(H00, H01+H10-2*H00, H11-H01-H10+H00)`, pesati dall'equality delle
coordinate rimanenti. Moltiplicarli per l'equality affine corrente e
per il fattore del prefisso produce gli stessi quattro coefficienti cubici.
Emettere/autenticare il round **prima** di conoscere la sua sfida; poi
piegare entrambi gli assi di H con quella stessa sfida. La finestra
successiva ricostruisce dal medesimo snapshot con il nuovo prefisso.

L'identità segue espandendo la multilineare sui due assi e scambiando
somme finite; i termini fuori diagonale sono indispensabili. Il test F97
con sfide dipendenti dal transcript confronta tutti i coefficienti e
le quattro valutazioni terminali originali. Il test gather precedente
controlla la ricostruzione dei child. Non sono prove Lean del reader
integrato né esecuzioni MAC. H resta privata, dipende solo da witness
fissato e sfide precedenti, non da righe VOLE future: la nuova algebra
non richiede NoPeek più debole. Le emissioni restano quelle di
[security §3](security.md#3-schedule-completa-e-destinazione-degli-endpoint).

Per scegliere le finestre prima di materializzare 25 bit, lo
[screen](../../scripts/c71_streaming_screen.py) enumera le composizioni
ordinate di g=m-25. A prefisso lungo p, una finestra b costa nel modello:

```
3*(N-2^(m+1)) + 4*2^m + (4+2*2^b)*2^(m-p) + (2^(2*b)-1) mul Fp3.
```

I termini sono merge, accumulo child, costruzione H e fold di H.
La costruzione H usa, per bucket, 4L mul per U/V pesati, poi 2L² mul
per i due prodotti esterni. L'equality del suffisso viene applicata
una sola volta. Fold dei due assi: L²-1 interpolazioni, ciascuna 1 mul
+2 add/sub. Generazione equality, estrazione cubica da H, riduzione
parallela, staging e MAC non entrano nell'obiettivo del planner.
È un minimo **soltanto di questo modello**, non del tempo o di tutti i
protocolli range. Il planner emette la tabella pubblica seguente:

| m | Finestre b | Visite, materializzazione finale inclusa |
|---:|---|---:|
| 25 | nessuna | 1 |
| 26 | 1 | 2 |
| 27 | 2 | 2 |
| 28 | 3 | 2 |
| 29 | 4 | 2 |
| 30 | 5 | 2 |
| 31 | 2, 4 | 3 |
| 32 | 3, 4 | 3 |
| 33 | 2, 2, 4 | 4 |
| 34 | 2, 3, 4 | 4 |

Sono 15 finestre, 10 materializzazioni e la costruzione del canopy:
26 visite. La H massima costa **24.576 B**, i suoi 4L child **3.072 B**.
Una H per *ogni* bucket contemporaneamente sarebbe un altro layout,
non ammesso: usare un numero fisso di worker e ridurre le H parziali.

| Conteggio W range | Replay precedente | Finestre variabili |
|---|---:|---:|
| Visite W | 56 | 26 |
| Payload W residente, B | 3.438.102.671.360 | 1.596.261.954.560 |
| Merge razionali | 1.305.602.949.119 | 640.151.453.695 |
| Accumuli child | 1.237.084.798.976 | 506.403.487.744 |
| Mul Fp3 per H | 0 | 709.743.345.664 |
| Mul Fp3 per coefficienti ordinari a 27/bucket | 927.712.934.964 | 9.965.665.332 |
| Nucleo confrontabile, mul Fp3 | 6.081.606.581.297 | 3.146.566.859.825 |

Il nucleo scende del **48,26%**. Le finestre fisse da 3 bit danno
29 visite e 3.508.417.854.513 mul; quelle da 4 bit danno 26 visite e
3.743.030.443.057 mul. Restano separati 1.845.493.580 fold residenti,
2.565 fold H e le voci escluse sopra. Gli add della costruzione H sono
581.095.653.376, oltre a un add per merge/accumulo.

Anche il coefficiente cubico residente si può fattorizzare: U0,dU,V0,dV
richiedono 4 mul, i coefficienti di UD+VB 8 mul, l'equality 6 mul:
**18 contro 27** nel riferimento diretto. Il nucleo così fattorizzato è
3.143.244.971.381 mul; il confronto sopra mantiene 27 in entrambe le
colonne per isolare l'effetto delle finestre. Il kernel preparato usa 18,
con il calcolo diretto come oracle di correttezza indipendente.

**Cambio di protocollo range.** Le finestre sono preferibili come prossimo
controllo perché conservano integralmente il transcript B12. Un oracolo
reciproco Z=(alpha-W)^(-1) eliminerebbe l'albero razionale, ma Z deve
essere impegnato privatamente prima delle sfide che ne verificano
l'identità. Autenticare liberamente il solo terminale dopo la sfida
consente di sceglierlo per soddisfare il test: questa scorciatoia è respinta.
La versione con una vera PCS privata di Z rimane aperta, con tre limb Fp
per valore Fp3, nuovi pad, righe MAC, byte, visite e bootstrap da censire.
Il margine iniziale di 3.105.466 B non dimostra che la nuova PCS ci stia;
non la si respinge solo perché un suo upper prudente lo supera.
Registrare il range di W una volta contro C_W può risparmiare il range W
successivo; serve aggiornare formalmente stato/FS e confronto su tutti i
prefissi. Non elimina il costo della prima proof o il range A.

## PCS coset, frontiere e sali riproducibili

Il [preflight](preflight.md) estende il precedente lower da 683 scansioni
con una schedule esplicita del **primo oracolo W**, non di tutta la PCS.
Con H=2^32, larghezza 128, L=2^22 righe per coset e Q=1.024, il coset
occupa 4.294.967.296 B. Emettere `c=0..Q-1`, poi `j=0..L-1`, con indice
naturale della foglia `Q*j+c`. Ogni j riceve consecutivamente le foglie
del proprio sottalbero da Q foglie, anche se le emissioni dei diversi j
sono intercalate. Conservare una frontier per j costa al più
`32*L*log2(Q)=1.342.177.280 B`. Nell'ultimo coset le radici dei sottalberi
arrivano in ordine j: uno stack superiore produce la **root originale**,
senza permutare foglie, dominio o commitment.

Il backend corrente è ancora incompatibile con la materializzazione:
crea quattro sali Fp per ogni foglia (137.438.953.472 B), oltre alla
codeword. Il seed del modello è già conservato e ripetibile, ma
l'assegnazione dei sali alle righe deve restare quella canonica. Cambiare
l'ordine dei draw al nuovo ordine c-major non riproduce la stessa root.

La soluzione individuata non introduce un PRG nuovo: il
[PrivateRng B12](../../rust/volta-pcs/src/c71_matrix/b12.rs) usa BLAKE3 XOF
seekable, con cap di 2^40 byte. Il sampler Goldilocks consuma u64 fino a
ottenere un valore <p. Un prescan dei sali nell'ordine canonico registra
la posizione byte iniziale di ogni blocco j da Q foglie. Nel replay
c-major, leggere dal medesimo seed alla posizione corrente di j, estrarre
quattro sali con il medesimo rejection sampling e aggiornare la posizione.
Conservare start/current costa **16L=67.108.864 B**. Il prescan non legge
W; produce almeno 137.438.953.472 B XOF, con consumo variabile per i
rifiuti. Ripristinare anche `remaining=2^40-position`; l'esaurimento
continua ad abortire. Seed, posizione di ingresso e sequenza dei clone
MMCS devono corrispondere al commitment originale, non essere scelti
nuovamente durante l'apertura.

Il controllo minimo Python usa una piccola sorgente seekable con rejection
sampling frequente: ogni sale riprodotto c-major coincide con quello
sequenziale. Verifica root, cammini delle query, replay dagli offset
iniziali e rifiuto di alterazioni. Non esegue BLAKE3/PrivateRng nativi:
l'adapter seek e il confronto bit-per-bit col backend restano da implementare.
È una derivazione di replay esatto, non una nuova ipotesi sui sali.

L'apertura dopo le query ricostruisce lo stesso encoding e conserva solo
i fratelli richiesti. La schedule semplice paga quindi **1.024 scansioni
W per commit e altre 1.024 per il replay dell'apertura**. Le query non
sono anticipate. Altri oracoli WHIR, maschere, switch e A/vecchie A devono
ancora essere integrati; non si attribuisce questo upper parziale a tutta
la PCS. Un tree globale riutilizzabile o un encoder per sottoinsiemi
potrebbe cambiare il costo e richiede un proprio census.

La FFT GPU letterale con un passaggio globale per ogni stadio è respinta:
il lower condizionato di sola banda supera 50 s per encoding. Una variante
senza seconda codeword fattorizza L=2048²: trasposizione quadrata in-place,
FFT di riga da 2.048 elementi, twiddle fuso con seconda trasposizione,
altra FFT di riga e terza trasposizione nell'ordine naturale. Servono
16 KiB shared per riga; nessuna di queste osservazioni è un upper di
registri o una prova del kernel CUDA. Il controllo finito Goldilocks
M=4/8/16 coincide con la FFT diretta. I cinque passaggi hanno 10 volte
il payload encoded come traffico logico, prima di hash/sali/reader.

Coset + frontier + stack superiore + twiddle completo + pad originali +
offset sali costano **5.739.381.472 B**, lasciando **703.069.472 B**
prima di hash/staging/allocator e altro stato vivo. La geometria non è
esclusa dalla sola arena. Campo, hash, XOF, layout e visite sono separati
nel preflight; il tempo completo rimane ignoto, così come source-uniformity
e confronto di lavoro totale. Né il nuovo replay PCS né il nuovo range
sono ancora port nativi o costruzioni fisicamente ammesse.

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
l’ipotesi EA-LPN-SL-reg* ora autorizzata sulla geometria dichiarata;
LogVOLE e Akita introducono
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

# A zero payload could not be charged as <=2^-78 in the relaxed predecessor.
zero_lower = Fraction(t, p)-Fraction(t*(t-1), 2*p*p)
assert Fraction(1, 2**54) < zero_lower <= Fraction(t, p) < Fraction(1, 2**53)
# Large-field candidate: full binary blocks and N=5n.
t, h, ell = 675, 19, 11
assert t*2**h == 353_894_400 and t*2**h//5 == 70_778_880
# Global path guard: one mask and two Fp3 wire scalars, no inverse rows.
path_seeds = t*(h+4)+3
path_guard_error = Fraction(t*h+1, p**3)
assert path_seeds == 15528
assert Fraction(1, 2**179) < path_guard_error < Fraction(1, 2**178)
assert 2**74*path_guard_error < Fraction(1, 2**104)
# Candidate Fp6 seed and Dory payload subtotal; no complete admission.
fp6_seed_wire = 146489+3120*path_seeds
fp6_subtotal = fp6_seed_wire+8*t+8*t*(h+3)+24*t*h+48
fp6_received = 3072*path_seeds+8*t+8*t*(h+3)+48
assert fp6_seed_wire == 48_593_849
assert fp6_subtotal == 49_025_897
assert fp6_received == 47_826_264
assert 130_000_000-fp6_subtotal == 80_974_103
assert fp6_received+47_841_180-25_210_128 == 70_457_316
assert 130_000_000-70_457_316 == 59_542_684
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
| [Succinct lattice ZK toolkit](../../sota/2026-1289-succinct-lattice-zk-toolkit.pdf), `https://eprint.iacr.org/2026/1289.pdf` | `fea3783839c0e1360e64e7f07e32677a3b1b66f79768448e914a3de5f8ef61e0` / `acc3b8b95a5895289f5d475d18fe0a585e8aafeefce10567474f3ec4975cb583` |
| [Ring-LPN PCG](../../sota/2022-1035-ring-lpn-pcg.pdf), `https://eprint.iacr.org/2022/1035.pdf` | `a3d0ed7d8669bcf62d867dcfb606f3a2bcb6bd25107aaa011a6189ed6d1821f9` / `07b039b80b231e66bc2c2c6d9dbc4a71e96e6d36518fe49aec145890405ee364` |
