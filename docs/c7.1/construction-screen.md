# C7.1 — Screen di nuove famiglie

2026-09-12 · [Contratto](design.md#owner-authorized-pcsstate-experiment) ·
[Screen precedente](pcs-state-screen.md#screen-minimo-sotto-i-tetti-assoluti).

**Esito: nessuna costruzione completa selezionabile, `credit:false`.**
La ricerca comprende bootstrap silent/streaming, chosen-input VOLE,
PCS con codici, sumcheck a memoria ridotta e PCS su reticoli con lookup
one-hot. Le esclusioni sotto riguardano le sostituzioni specificate;
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
[Shout](https://eprint.iacr.org/2025/105), è la pista più interessante
fra quelle esaminate per evitare sia i codeword RS sia i 256 nodi foglia
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
