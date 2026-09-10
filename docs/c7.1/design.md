# C7.1 — Current construction and requirements

[Status](status.md) · [Security](security.md) · [Evidence](evidence.md) · [Decisions](decisions.md)

Questo è il contratto tecnico corrente. La specifica eseguibile matematica
è definita una sola volta in [security §§1–3](security.md#1-enunciato-e-oggetti-fissati).
I dossier precedenti conservano derivazioni e fallimenti delle rispettive
costruzioni; non si importano da essi vecchi mandati, profili o sottototali.

## Relation and model

L'accettazione deve attestare un'inferenza intera della versione quantizzata
intera dichiarata, inclusi token e KV, su **un solo W privato installato**.
Ogni collegamento fra produttore e consumatore conserva lo stesso valore
autenticato; l'apertura PCS termina nel MAC originale richiesto dal calcolo.
Un MAC valido di un valore libero non dimostra che quel valore sia W(r).
Il verifier conserva Delta/chiavi, senza ricevere W o i tag grezzi privati.

Il riferimento text-only è `google/gemma-4-31B`, revisione
`5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89`, con metadata SHA-256
`1ddce0cc399d636488728f663fb756804a07e6b3ad14d43f527c7ad746e27ce2`:
772 tensori privati, 60 scalari pubblici, embedding/head legati allo stesso
sorgente fisico. Il nome storico dei file `gemma31b` non cambia il checkpoint.
Il commitment attesta i pesi installati, non la loro provenienza dal
checkpoint o l'uguaglianza con BF16. Provenienza, quantizzazione e qualità
richiedono una valutazione o relazione separata.

Γ contiene metadata/DAG/layout pinned, esponenti comuni, scalari BF16
interpretati come dyadic esatti, epsilon RMS positivo e ricette certificate.
RNE è ties-to-even con overflow reject; argmax sceglie l'ID minimo a parità.
Sono selezionati `C71-RoPE-Q30-v1`, `C71-GELU-RNE-v1`, softcap certificato e
`C71-SOFTMAX-EXP30-v1`, con e_Pi=-14. Il verifier prepara e valida Γ prima
di W/bootstrap/prova e ricompila sorgenti e ricette dai dati pubblici.
Un digest o un oggetto `Sources`/`Recipes` consegnato dal prover non è autorità.
I dettagli esatti del profilo sono in [security §1](security.md#1-enunciato-e-oggetti-fissati)
e nelle [derivazioni applicabili](#assumptions-and-component-dependencies).

Tokenizzazione, chat template, token speciali e regola di arresto devono
coincidere con il profilo istanziato; tutti i token occupano il contesto.
La relazione selezionata ha 100 token di prompt e 50 generati per tentativo.
La coda certificata contiene K/V di tutti i 150 token, compreso l'ultimo
emesso, senza emettere un cinquantunesimo token per completarla.

Il campo è Goldilocks `p=2^64-2^32+1`, con `Fp3=Fp[u]/(u^3-2)`:
8 byte per elemento base, 24 per elemento Fp3. La composizione B12 e Lean
usano `k=m+Delta*x`. I dossier iniziali usavano `m=k+Delta*x`: il trasferimento
richiede `Delta_old=-Delta_native`, mantenendo x/m/k. La negazione va
applicata coerentemente, non soltanto nella notazione. Tag privati grezzi
permetterebbero al verifier di recuperare x; si emettono soltanto i messaggi
mascherati o i residui previsti dalla prova di simulazione.

## Setup and accepted state

`ModelSetup(W, Γ, model_coins)` è indipendente da Delta, chiavi VOLE,
correlazioni, utente, prompt e attempt. Questa non dipendenza riguarda
anche i dati letti dal codice. Produce il modello privato e C_W;
cambiare Delta a parità degli altri input non cambia gli artefatti modello.
Il setup DV/capacità è separato e non ricodifica W per ogni risposta.

Il profilo attuale ha una nuova installazione, un solo setup AES e key epoch,
una capacità iniziale e al più tre tentativi a O=0/150/300. Si parte da KV
vuoto; sono ammessi solo i predecessori promossi dal registro locale del
verifier. Nessuna cache o ricevuta importata sostituisce quella premessa.
Tutta la catena conserva C_W; vecchie A sono sorgenti immutabili di code.

Il setup B12 fixed-run usa `C71B12F1`, suite 3, con profondità AES GGM
fino a 24 e nove sacrifici separati. Il seal fresco del verifier segue il
bootstrap, nello stesso key epoch. Slot e intervallo contiguo di righe
sono bruciati prima dell'uso. Ogni nuova PCS, comprese quelle di vecchie A,
usa correlazioni fresche del tentativo corrente, con domini separati.
La capacità selezionata è specificata in [security §6](security.md#6-risorse-riuso-formale-e-confine-runtime).

Nella prova non vi sono challenge online del verifier: un solo transcript
FS lega Γ, roots, registro ordinato, sessione/epoch/seal, slot/intervallo,
nonce, prompt e token. Sfide interattive o prefissate sono solo diagnostiche.
L'attivazione iniziale può comprendere scambi offline; il loro costo resta
visibile. Non introduce sfide future note prima dei messaggi controllati.

Inferenza e prova si susseguono per un solo utente; non si avvia la risposta
successiva prima di completare la verifica. Il testimone rimane disponibile
fino all'ultimo consumatore; ogni replay conserva gli arrotondamenti e il
suo lavoro viene contato. Solo la chiusura congiunta di tutte le verifiche
promuove A e rende i token verificati. Un ACK non promuove nulla.
Errore, abort, esaurimento o perdita del processo terminano il run:
nessun reopen, rollback, rinnovo, nuova chat o cambio di root estende questo
teorema. Le estensioni sono registrate separatamente in [decisions](decisions.md).

## Sources and mandatory composition

W usa `Flat(D35)` con range i16 simmetrico; ogni A usa `Flat(D34)` byte.
Ordine Boolean MSB e suffisso zero sono comuni a reader, range e PCS;
il padding interno dei rettangoli è verificato dai produttori e dalle forme.
W, raw, byte biased, istogrammi e trace sono snapshot immutabili preparati
prima delle emissioni di prova, senza leggere correlazioni inutilizzate.
Un fallimento privato della preparazione espone solo `Stop` prima di C_A.

La [schedule obbligatoria](security.md#3-schedule-completa-e-destinazione-degli-endpoint)
definisce ordine e destinazione di ogni endpoint: P0, RMS/statistiche,
RNE originali e da sonde, GELU, gate-up, RoPE, QK/PV, KV, output,
EXP30, forme pubbliche, range/padding e PCS finali. I bias conservano
originali e tag; non si riautentica un endpoint per chiudere un obbligo.
Le tabelle e le forme appartengono alla stessa versione finale di A.
Non si crea una PCS per token, operatore, bit, logits o KV.

I conteggi finali di target, aperture, alberi, stream e correlazioni sono
mantenuti **solo in security §§3 e 6**. I precedenti conteggi incrementali
nel notebook e nelle singole prove componenti non si sommano al totale.
Il preflight pubblico usa tabelle in parte sintetiche: il suo conteggio
specifico non sostituisce quello conservativo della dimostrazione.

## Assumptions and component dependencies

Si richiedono almeno 78 bit per ciascuno dei due vantaggi **completi**.
Il teorema corrente è nel ROM classico con `T_A=M_A=2^80`, inclusi ambiente,
preprocessing e advice, e `Q_A=2^64` globale, inclusi candidati FS scartati.
Le riduzioni complete restano sotto `T_R=2^121`, `M_R=2^93` e `Q*=2^74`.
Le ipotesi primitive sono AES-256 PRP a quattro blocchi con vantaggio
`<=2^-128` e DDH P-521 `<=2^-193` **a T121/M93** nel modello dichiarato.
Sono ipotesi computazionali esplicite, non vantaggi concreti dimostrati dal
nome delle primitive, dai loro test o dall'ipotesi storica a M89.
Nessun setup onesto aggiuntivo è assunto. ZK parte da nuova installazione,
non da una root arbitraria fissata esternamente; tempi/accessi fisici e
side channel non appartengono alla vista matematica simulata.

Le seguenti parti del notebook restano derivazioni tecniche applicabili
entro il profilo selezionato. La loro prosa di stato e i loro sottototali
precedenti sono storici; per il risultato congiunto vale [security](security.md).

| Dipendenza | Derivazione e perimetro del riuso |
|---|---|
| Bootstrap reale → ideale, AES finito e seal | [B11 AES](../c7.1-gemma31b-design.md#b11-selezione-intermedia-aes-a-capacità-finita), [B12 T80/seal](../c7.1-gemma31b-design.md#b12-risorse-lifetime-e-vincolo-same-w), [setup unico esteso](../c7.1-gemma31b-design.md#b12-capacità-aes-iniziale-per-il-run-continuo); usare S=1 e M93 correnti, non il vecchio lifetime S20 |
| Root fissata al prefisso → unico messaggio → MAC | [PCS B12](../c7.1-gemma31b-design.md#b12-pcs-unicità-del-messaggio-e-compilazione-privata): MCA con `3*tau<d`, decoder unique-radius, Merkle salato con preimage differiti, blocchi di coin FS e chiusura scalare nativa; nessuna congettura di lista o trasposizione automatica del fork |
| Parametri PCS | Nella stessa derivazione: `t_i=t_zk=512`, pad iniziali 1536, successivi 512, `ell_zk=2048`, `r_zk=512`, `H_zk=32768`, geometria `H=next_power_of_two(8*(M+r))`, `tau=H/4`; D35/D34 come sopra |
| Privacy PCS/MAC con endpoint condivisi | [Traslazione claimless](../c7.1-gemma31b-design.md#b12-zk-del-consumer-claimless-nel-run-continuo) e [simulatore congiunto](security.md#5-simulatore-congiunto-e-nopeek): un solo W fittizio e una traslazione per sorgente su tutte le esposizioni |
| Semantica numerica e copertura dei produttori | [Profilo comune](../c7.1-gemma31b-design.md#b12-profilo-numerico-comune-ricette-derivate-dai-produttori), [EXP30](../c7.1-gemma31b-design.md#softmax-exp30-baseline-intera-selezionata), [Q30](../c7.1-cut-witness.md#rope-geometria-adjoint-e-limite-q30), [GELU](../c7.1-cut-witness.md#gelu-tabella-rne-certificata); ricette certificate, non placeholder del preflight |
| Dal campo agli interi e alla storia KV | [Soundness composta](security.md#4-soundness-dalle-aperture-alla-transizione-accettata): envelope `<p`, range specifici dei produttori, originali e induzione causale, compreso il token finale |
| Risorse della riduzione e trasferimenti Lean | [Security §6](security.md#6-risorse-riuso-formale-e-confine-runtime): quattro decoder nella riduzione, nessuno nel verifier ordinario; lemmi applicabili e premesse del trasferimento esplicite |

## Native correspondence

Il port canonico deve dimostrare la corrispondenza fra il codice composto
e [Prepare/VerifyResponse](security.md#2-preparatore-e-macchina-di-accettazione).
Le API componenti restituiscono obblighi pendenti: il loro successo non
implica già un'inferenza Gemma accettata. I collegamenti da verificare sono:

| Confine | Proprietà richiesta |
|---|---|
| Γ/semantica → snapshot | Stessi operatori, esponenti, arrotondamenti, overflow, token e coda; input del preparatore indipendenti da MAC/FS |
| Snapshot → P0/GKR/RNE/lookup | Copertura dei produttori e alias originali, punti/gradi/ordine esatti; getter immutabili e NoPeek effettivo |
| Endpoint → range/PCS | Stessi valori, key e domini; consumare tutti gli originali una sola volta nei batch previsti |
| Certificato → transcript | Codec canonico completo, cardinalità obbligatorie, framing finale, un solo FS ricostruito dal verifier |
| Verifica → registro | Proprietà locale di W/Γ/stato, burn prima dell'uso, nessuna promozione parziale, rifiuto terminale e ultimo KV completo |

La mappa dei lemmi in security §6 non è una prova Lean del fork PCS o del
wrapper Rust. `OpeningMac` presuppone binding/indipendenza nel proprio
esperimento; i lemmi di promozione presuppongono code ammissibili.
Non si eredita un vecchio numeratore Lean né la correttezza Gemma dal
golden GPT-2. L'output effettivo del compilatore deve corrispondere alla
relazione, non soltanto a una lista di conteggi condivisa.

### Executed bounded path

Il [percorso nativo ridotto](../../rust/volta-pcs/src/c71_matrix/gemma/native.rs)
esegue tutte le famiglie della schedule su un layer locale, hidden e
vocabolario 2, prompt 1 + generato 1, O=0/2/4. Usa gli stessi kernel
P0/RMS/RNE/lookup/gate-up/RoPE/QK/PV/KV/EXP30, le forme byte originali,
range e PCS salata. GELU riusa la vista tabellare del caller output con
la propria tabella e i propri ID. Il compilatore ridotto è esplicito;
non sostituisce `Recipes::compile` o i descrittori pinned.

Γ ridotto fissa ex=ew=ey=0, Pi=-14, epsilon RMS=10^-6, coefficienti
affini identità, RoPE Q30 j=0 alle sei posizioni assolute, GELU su [-2,2],
softcap su [-4,4] ed EXP30 su D=0..7. Le tabelle sono restrizioni delle
ricette selezionate, controllate con il generatore certificato Python.
Un input privato fuori da queste restrizioni produce solo Stop. Questo
profilo non è una calibrazione o un'istanza del checkpoint Gemma completo.

`Installed` fissa W (46 i16, Flat D10) senza input DV; `Snapshot::prepare`
produce tutti i raw, gli i16, gli istogrammi e i byte di A (69 sorgenti,
Flat D12) senza FS, Delta, tag, righe o seed PCS in ingresso. Le due righe
sono calcolate causalmente, compreso il KV del token emesso. C_A è creata
solo dopo il successo di tutta la preparazione. Il preflight di capacità
precede le letture private. Dopo le sfide i getter prendono soltanto
riferimenti immutabili allo snapshot e agli originali W.

Il compilatore verifica un produttore per ogni sorgente. Il dispatcher
chiude 18 target W, 110 target A corrente e uno per vecchia A: sette RNE
consumano MAC/punti originali, dieci usano sonde intere. Range W i16
simmetrico, range A byte e padding sono obbligatori. Ogni risposta ha
2/3/4 PCS, una per sorgente, con righe fresche; le riserve complete sono
88.049/88.562/89.102 Fp3 (797.139 righe base equivalenti nel run).

Il codec ridotto usa frame `(u16 ordine, u32 lunghezza, payload)`, conteggi
interni canonici e Fp3 canonici; il payload PCS riusa il codec esistente.
I 17/18/19 frame sono obbligatori e assorbiti nello stesso FS dei kernel.
Il verifier ricostruisce header, profili, storia ordinata e forme dal
proprio stato. Lunghezze/vettori sono limitati prima dell'allocazione
(16 MiB totali, 65.536 elementi per vettore); il record finale vincola
conteggio e lunghezza e richiede EOF prima del digest di completamento.

L'ingresso della verifica rende subito terminale il run. Slot e intero
intervallo vengono bruciati prima del decoding dei componenti; anche
panic/esaurimento FS si traducono in Stop. Solo il successo di tutte le
verifiche e del framing aggiunge la nuova voce al registro. Il prover
mantiene lo snapshot pendente e lo promuove tramite un oggetto di
accettazione costruibile solo dal verifier completo, non da un ACK wire.
Non esistono API di clone/import delle ricevute, rollback o reopen.

**Limite del trasferimento:** questi sono controlli eseguiti della
composizione ridotta nel modello di correlazioni indipendenti ideali.
I lemmi MAC/prefissi/KV sopra si applicano alle medesime equazioni e
regole di stato, senza costituire una prova Lean del wrapper. Restano
da eseguire il dispatcher canonico e la composizione positiva AES/journal;
non sono provati un raffinamento generale Rust, i bound 82,93/91,02 per
questa istanza ridotta o uno schedule fisico. Il runner di produzione
non acquisisce un backend ideale o un fallback CPU da questo modulo interno.

### Canonical producers and real-pool adapter

Il [compilatore canonico](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical.rs)
riusa `compile`, `softmax_sources_at` e `Recipes::compile`. La scala comune
resta input pubblico del verifier; questa fase non certifica le tabelle
né calibra il checkpoint. Compila 2.328 produttori e verifica un solo
produttore per ognuna delle 3.471 sorgenti finali, comprese raw, statistiche,
istogrammi e slack. L'ordinamento causale deriva dalle identità delle
sorgenti, non soltanto dai conteggi. Conserva le forme dei descrittori,
inclusi i dieci alias globali dell'input K/V prima della normalizzazione.
Non esegue ancora quei produttori: selezione delle righe, maschere causali,
letture delle code e assorbimento del token finale devono essere rispettati
dal futuro preparatore canonico, senza materializzazione densa locale.

Il [collegamento al pool](../../rust/volta-pcs/src/c71_matrix/gemma/native/pool.rs)
usa esclusivamente `prover_fixed_run`/`verifier_fixed_run`: il contesto
pubblico del pool confronta W/semantica/sessione, seal, setup, ordinale,
primo indice base e predecessore col registro locale. Tre righe base
consecutive diventano una Fp3 con `Delta_native=-Delta_B11`. Prepare
precede l'accesso alle correlazioni; capacità insufficiente si controlla
prima delle letture private. Il pool brucia l'intera riserva prima del
callback, e scrive l'accettazione prima della promozione del registro.
Un errore anche prima della riserva termina il pool e ne cancella le righe.
Il prover richiede l'oggetto `Acceptance` creato dal verifier completo,
non un digest ACK fornito dal peer. Il trasporto distribuito di questa
capacità di accettazione resta da definire; l'adapter è interno.

Gli ingressi basati su iteratori MAC ideali sono ora `cfg(test)`. La
validazione dell'adapter comprende packing/segni/contesto e rifiuto reale
con tre righe AES; non comprende ancora la composizione positiva da
797.139 righe base, né il port dei produttori numerici al grafo canonico.
I [limiti di esecuzione](../procedures/build-and-test.md) rimangono invariati.

### Shared integer RMS preparation

`rms::Integer` deriva gli stessi coefficienti ridotti, epsilon 10^-6,
range simmetrici e limite aritmetico u128 usati da `rms::compile`.
Calcola RNE con confronti delle mezze soglie al quadrato, senza floating
point; segno, parità, output zero e overflow seguono il circuito.
`row` calcola S dalla somma dei quadrati degli input e P dai pesi effettivi:
il caller non fornisce una statistica o un output di normalizzazione.

`Norm::prepare_row` divide un token per teste usando colonne/teste del
descrittore, ripete gli stessi pesi per testa e distingue le norme pesate
dalle V senza parametro. Restituisce statistiche per testa e P/Y in ordine
head-major. Il preparatore ridotto usa già questo percorso; il dispatch
numerico canonico deve ancora collocare i risultati nei rispettivi raw,
statistiche e output, con gli alias e le righe selezionate del DAG.
Non vengono eseguiti snapshot completi o PCS D34/D35 da questi helper.
Il limite u128 esistente resta un rifiuto pubblico, non viene ampliato.

### Canonical verifier body

Il [corpo canonico](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_verify.rs)
esegue le chiamate di security §3 sui descrittori di `Canonical`, con un
unico Fs costruito dal wrapper interno. Riusa `Reader` e `Batch` del percorso
ridotto, senza modificare il suo transcript. Prima di espandere le forme
pubbliche controlla identità delle ricette/layout/PCS e uguaglianza fra
riserva fornita e `Recipes::required`. Ricostruisce il P0Statement interno
con il layout effettivamente posseduto dal compilatore. Le 410 RNE consumano key e punti
originali; le 482 sonde, le 120 richieste K/V e i batch finali conservano
le identità delle sorgenti. Sono implementati i confronti 775/4.446 target,
una PCS per ogni sorgente, consumo esatto e framing finale con EOF.

L'ordine implementato comprende frame 0–7 per forme/P0/RMS/RNE/GELU/gate/RoPE,
8–127 per le coppie QK/PV dei 60 layer, 128 per KV, 129–130 per softcap/EXP30,
131–132 per range, 133 per W, quindi vecchie A e A corrente: 135/136/137
frame complessivi. È un ordine del codice, non una misura di certificati
canonici prodotti. Il cap di trasporto riusato resta 16 MiB e non è
dimostrato sufficiente per il certificato completo.

`verify_body` è un consumer interno, non `VerifyResponse`: non riserva
correlazioni, non costruisce l'header dal registro, non certifica Γ e non
promuove uno stato. Registro dei segmenti, Fs iniziale e riserva già bruciata
sono obblighi ora implementati nel wrapper interno seguente. Il digest
restituito non è l'oggetto `Acceptance` del percorso ridotto. La verifica positiva dell'intero
corpo, Prepare/prover canonici e il codec completo restano da eseguire;
i controlli del prefisso non trasferiscono i bound matematici al runtime.

### Canonical registry and real pool

Il [wrapper interno](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_state.rs)
compila i tre contesti da un'unica mappa di scale e conserva riferimenti
immutabili alle tabelle attese del verifier. Il digest pubblico include
ricette, layout, corpi completi GELU/EXP30/softcap, finestre RoPE con
posizioni e riserve; le tabelle non posizionali devono coincidere nei tre
slot. Questo digest alimenta `ModelBinding.semantics`, distinto dal digest
di sole ricette usato dai kernel. La validità numerica di Γ resta una
premessa non scaricata: il wrapper è interno, senza ammissione pubblica.

L'installazione ammette solo un pool fixed-run fresco con W/Γ/sessione
coerenti. `verify_response` rende immediatamente terminale lo stato,
controlla prompt 100, token 150 nel vocabolario e freschezza di A, poi
ricostruisce l'header `C71B12-Gemma-FixedRun-v1` dal registro ordinato.
Il confronto del pool vincola seal, setup unico, slot, predecessore e
cursor. `Pool::attempt` brucia la riserva prima del decoding; il wrapper
compone le chiavi col segno nativo e passa al corpo soltanto segmenti
ricostruiti dalle accettazioni locali più A corrente. Il successo del
corpo genera `Acceptance`, aggiunta al registro solo dopo il journal.
Errori e panic terminano stato e pool; il risultato esterno è solo `Stop`.
Non esiste un ingresso per importare storia, chiavi o ricevute del peer.

Il limite Fs interno è 2^42 richieste, ripreso come arresto operativo
dall'envelope analitico di security §6, non come misura o dimostrazione
del numero di draw del programma. Restano il cap di trasporto 16 MiB e
i limiti PCS preesistenti: non si assume che ospitino il certificato
canonico completo. I controlli del registro e del rifiuto AES a tre righe
non percorrono la promozione positiva; la sua corrispondenza, il preparatore,
il prover, la certificazione numerica e lo schedule fisico restano aperti.

## Resource and measurement contract

| Voce | Riferimento da soddisfare; nessuna nuova misura |
|---|---:|
| Prover completo a modello residente | 45–50 s |
| Certificato completo per risposta | preferenza 30.000.000 byte; allarme oltre 35.000.000 |
| Verifier CPU locale, quattro core | 6,4–8,2 s |
| Caricamento modello per residenza | riferimento storico 19,186 s, distinto dal setup crittografico |
| Inferenza e prover sulla stessa H100 | picco globale <80.000.000.000 byte |
| Letture packed W per la prova, oltre all'inferenza | fino a quattro; due restano un'ottimizzazione |
| Arena temporanea complessiva | 6.442.450.944 byte |
| W packed | 61.394.690.560 byte |
| Materiale modello persistente, W inclusi | ≤2,10× W packed =128.928.850.176 byte |

Queste sono preferenze, limiti e allarmi del riferimento, non autorizzazioni
a indebolire privacy o soundness. Nessuno spill, seconda copia dei pesi o
codeword completo è ammesso nel riferimento. Il trattamento delle sorgenti
richiede `c_source*N + P(q,h)` con coefficienti uniformi indipendenti da q/N;
nessun `qN`, `N log q` o `N log N` si nasconde sotto GKR o witness.
La dimensione del circuito/token rimane una voce distinta del lavoro completo.
Le letture W per ricostruire il witness, anche rieseguendo il forward,
consumano il limite della prova. Prima che l'output fissi il prefisso FS si
prepara solo ciò che non dipende dalle sfide successive; non si anticipa
il folding. La cache accettata resta valida preparando il successore,
senza una seconda cache completa o alias che sovrascrivano dati ancora vivi.
Il teorema denso con codeword W da 4 TiB e A da 2 TiB è fisicamente escluso.

Tempi prover includono generazione, preparazione witness, espansione PCG,
prova e serializzazione. Separare setup, caricamento, trasporto e verifica
non sottrae lavoro dipendente dalla risposta. I byte completi includono
framing, roots, salts, indici/path, coefficienti, correzioni, prodotti,
range/lookup/padding. Ogni record ha produttore, consumatore, cardinalità,
encoding, dominio e consumo VOLE; una correzione Fp3 generica costa 24 byte.
Contare una volta i byte offline già ricevuti, di nuovo i riferimenti ritrasmessi.
Un costo ignoto ha bound di ammissione infinito, non costo zero.

Il picco comprende ciò che coesiste: W, KV, modello/runtime, testimone,
alberi, staging, GKR/PCS/PCG, maschere, attivazioni, workspace e allocator.
L'arena comprende tutti i temporanei controllati dall'implementazione;
capacità riservata e occupazione logica sono distinte. Riuso e rilascio
richiedono l'ultimo consumer e il completamento GPU. Registrare memoria
trattenuta fino alla terminazione. I 2,10× persistenti non sono capienza HBM.
Le letture W non contano automaticamente tutte le letture dei temporanei.

Il verifier conta decoding, hash, campo, GKR/PCS, espansione PCG, MAC e
aggiornamento dello stato. Il limite è quattro worker complessivi, senza
pool annidati che lo moltiplichino; registrare thread, affinità, CPU/wall time,
RSS e backend AES. Non gli si richiedono W, GPU o un servizio remoto.
La [CPU osservata e i dati storici](../c7.1-gemma31b-design.md#81-cpu-del-verifier-riferimento-effettivamente-osservato)
non autorizzano equivalenze di prestazioni tra ARM e x86.

Il vantaggio di Goldilocks/DV resta da misurare sul prover completo, PCG
incluso, a garanzie equivalenti. Per confrontare altri sistemi fissare prima
lo stesso operatore, poi modello, quantizzazione, token, hardware, thread,
preprocessing e privacy. I [confronti OpenLLM/DeepProve](../c7.1-gemma31b-design.md#9-confronto-corretto-con-openllm-e-deepprove)
restano riferimenti di carichi diversi, non fattori di accelerazione Gemma.
Misurare prodotti Fp e Fp3 separatamente senza sommare viste sovrapposte,
letture/scritture HBM, trasferimenti CPU/GPU e storage; overlap e vantaggi
delle fusioni richiedono una timeline e confronti accoppiati. Decodifica
speculativa opzionale solo a sequenza identica, con modello di bozza e
lavoro scartato inclusi. Le ottimizzazioni algebriche archiviate richiedono
controlli bit-per-bit e misure dei kernel reali, non crediti da roofline GPT-2.

Il profilo matematico selezionato si ferma a 450 token. Il futuro confronto
Gemma fino a 4.096 token totali (vecchi+prompt+generati) richiede nuovi conti
e composizione: i tempi obiettivo riguardano il primo 100+50. Il layout KV
i16 usa 901.120 byte/token e 3.690.987.520 byte a capacità 4.096. La capacità
vuota non diventa arena aggiuntiva senza una prova di liveness/padding.
Size massima, lavoro e memoria vanno ricompilati per ogni carico; niente
medie o somme di sottototali incompatibili. Le varianti a cinque letture,
spill host e aritmetica ibrida sono [opzioni differite](decisions.md#deferred-requirements-and-options).

Le procedure e i limiti delle verifiche locali sono in
[build-and-test](../procedures/build-and-test.md). I test documentali non
richiedono build Rust/Lean; E2E pesanti e hardware richiedono l'autorizzazione
pertinente. Il port su grafi piccoli non autorizza allocazioni D34/D35,
benchmark Gemma o spesa. La produzione usa real/AES PCG e fallisce chiusa,
anche quando l'esecuzione GPU richiesta non è disponibile.
