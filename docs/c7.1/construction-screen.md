# C7.1 — Screen di nuove famiglie

2026-09-12 · [Contratto](design.md#owner-authorized-pcsstate-experiment) ·
[Screen precedente](pcs-state-screen.md#screen-minimo-sotto-i-tetti-assoluti).

**Esito: nessuna costruzione completa selezionabile, `credit:false`.**
La ricerca comprende bootstrap silent/streaming, chosen-input VOLE,
PCS con codici, sumcheck a memoria ridotta, lookup frazionari e PCS
hiding su reticoli o gruppi bilineari. Le esclusioni sotto riguardano le sostituzioni specificate;
non sono un'impossibilità per tutte le combinazioni di queste famiglie.
Non si implementa né si ottimizza una linea già respinta.

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

**Nessuna nuova candidata completa supera lo screen.** La combinazione
più interessante sul solo piano strutturale è **LogUp-GKR + PCS Dory
con valutazione impegnata**: cambia anche il consumer e dispone già di
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
```

Fonti lette nei Markdown conservati: [Dory PCG](../../sota/2025-1660-dory-streaming-vole.md),
[LogVOLE](../../sota/2026-0925-logvole.md), [LiftWHIR](../../sota/2026-1561-liftwhir.md),
[Brakedown](../../sota/2021-1043-brakedown.md), [Jagged](../../sota/2025-917-jagged-pcs.md),
[Scribe](../../sota/2024-1970-scribe.md), sumcheck e Akita sopra.
Metadati verificati sulle pagine IACR; per Shout basta l'abstract primario
per identificarne il ruolo, senza attribuirgli un port o un costo C7.1.
Il nuovo [PDF Akita](../../sota/2026-09-12-akita.pdf) proviene da
`https://assets.layerzero.network/pdf/akita.pdf`, scaricato il 2026-09-12
e convertito localmente con AnyDoc 0.1.7. SHA-256 PDF:
`b82969386ed3f006cf86ba95eb0ab02cd9f741ae79c98611680531b81a34f67d`;
Markdown: `566fe8c55c55bf331eb243872d66dbdbacb2df33b7642118c65e15ad44e608c6`.

Nuove fonti del secondo screen, acquisite il 2026-09-12 e convertite con
AnyDoc 0.1.7; nessuna fonte precedente sovrascritta. Metadati primari:
[sumcheck](https://eprint.iacr.org/2026/587),
[Jindo](https://eprint.iacr.org/2026/044),
[Dory PCS](https://eprint.iacr.org/2020/1274).

| PDF conservato / URL di acquisizione | SHA-256 PDF / Markdown omonimo |
|---|---|
| [Sumcheck](../../sota/2026-0587-speeding-up-sumcheck.pdf), `https://cs.nyu.edu/~zd2131/papers/26-587.pdf` | `04ac867dc2d2e68f967bbb4550c1afe1340439e8b0aae1611464c4e433f8a1a7` / `630c077243d532bebfeb7b20cdc28280da40990439c6adcd101e23e2889d4f20` |
| [Jindo](../../sota/2026-0044-jindo.pdf), `https://eprint.iacr.org/2026/044.pdf` | `ebf0f9634b2d6a5c42e8f4810a7b9da07c3edd760cfca3d5a8159838d2bdc70e` / `c75c0bf0539a42ad4887c6cb1df54e635bfa09367910901b6a53d59224f45bc4` |
| [Dory PCS](../../sota/2020-1274-dory-pcs.pdf), `https://eprint.iacr.org/2020/1274.pdf` | `d0789bc9497d5532b53065176ed3c85d5d3360b23d20fd7e839174ec23518a52` / `b78c7f401ee77c6fadaa991a9287a815f0a6da960d3e115055db718e116d42a6` |
