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

**Estensione autorizzata dal proprietario il 2026-09-12.** Il trust model
del goal di riduzione è ora **B12 + EA-LPN-SL-reg\***, con la premessa
concreta proposta:

```text
Adv_EA-LPN-SL-reg*(675,70778880,353894400,11,Fp;
                  T=2^121,M=2^93,one-leakage) <= 2^-80.
```

È una premessa accettata, non un risultato della regressione empirica LPN.
Non richiede altra approvazione per proseguire il lavoro locale su questa
geometria. Restano da verificare il trasferimento compositivo del bootstrap,
il codec e le risorse; il teorema B12 v1 sotto rimane il riferimento già
dimostrato. L'estensione non introduce ipotesi lattice o un setup fidato PCS.

Lo [screen Wasp del 2026-09-25](construction-screen.md#wasp-pcs-vole-ahe-e-limiti-del-port)
studia una PCS VOLE-AHE con apertura univariata corta. BGV/RLWE, circuit
privacy e polynomial linear targeted malleability restano premesse **non
selezionate**. La PCS pubblicata apre y in chiaro; l'identità candidata
negli originali MAC richiede validazione del setup contro verifier malevolo,
simulazione sui rifiuti, riduzione MLE e collegamento al W installato.
Un controesempio con potenze SRS incoerenti esclude il solo adapter finale
senza tali protezioni. Nessun bound B12 o risultato fisico si trasferisce;
setup cifrato e stato di sessione devono essere contabilizzati integralmente.

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

Il raccordo ridotto streaming usa `ordered::Reader` fissato prima delle
sfide: replay dei soli logits causali per determinare il token, validazione
di tutti i producer con i token finali e poi cut/KV privati immutabili.
`ReplayModel::new` costruisce davvero la root dal getter, dai pad e dal salt;
la proof ricommitta con le monete iniziali e controlla la stessa root.
Range e linear rigenerano i valori senza polinomio A o Eq(N) densi e
passano il terminale autenticato originale al backend WHIR replay. Le
conversioni tra tipi PCS spostano i payload senza roundtrip JSON. I test
con monete fissate controllano transcript, wire e MAC; i punti di ingresso
ordinari continuano a usare monete fresche da OsRng.

Il getter riceve soltanto indici e possiede W/cut/token già fissati, senza
accesso a FS o correlazioni. Le celle pubbliche tra `live` e DOMAIN_A sono
zero anche quando il dominio PCS eccede quello minimo del layout. Il
profilo selezionato dal nuovo reader è esplicitamente O=0; storia A e
real-PCG non acquisiscono credito dalla prova positiva. La rigenerazione
ricorsiva CPU è un riferimento di correttezza, non la schedule canonica
512 replay. I contatori per fasi includono ogni replay in proof work;
le callback annotate in GKR/lookup non addebitano una seconda copia del
lavoro del getter.

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

### Shared integer preparation

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

`rne::integer` copre le stesse 64 classi del predicato: shift ≥48
producono zero; shift ≤-15 ammettono solo raw zero; le altre classi usano
scaling esatto e RNE signed. Verifica il range signed-48 prima di ogni
caso, anche quando l'output sarebbe zero, ed esclude -32768 dall'output.
`Bytes::prepare_rne_row` riusa la validazione raw/output/shape del verifier
per le 892 coppie, senza accettare un output quantizzato dal caller.
Il preparatore ridotto usa questo percorso al posto di `1 << shift`,
che non copriva gli shift negativi o grandi ammessi dal profilo.

La divisione intera comune `rne::divide` serve anche il Pi del preparatore
ridotto: denominatore positivo, parità su entrambi i segni e overflow
reject. Il confronto del resto con `d-r` evita overflow di `2*r`.
È il solo arrotondamento, non il controllo dell'intera relazione EXP30:
range di E, maschera causale, somma Z e scala Pi restano responsabilità
runtime del produttore softmax e del circuito ratio già esistente.

`Bytes::prepare_affine_row` calcola R=aX+bY usando lo stesso validatore
di descrittori di `affine_zero_form`: raw a sei byte, ingressi a due byte,
forme identiche e coefficienti di modulo al più 2^30. Verifica la lunghezza
delle due righe e il range i16 prima dei prodotti. Due termini così
limitati hanno modulo al più 2^46 e rientrano in signed-48/i64; non c'è
un nuovo arrotondamento. Il preparatore ridotto usa già questa funzione.
Il controllo canonico valuta tutte le 181 relazioni nei tre contesti con
righe sintetiche, coefficienti del profilo ed estremi ammessi, confrontando
con aritmetica i128 e verificando i rifiuti. Non esegue lo snapshot canonico
né legge pesi reali. Le premesse del bound del verificatore non cambiano.

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
canonici validi prodotti. Il framing sintetico e il cap canonico da
96 MiB sono verificati sotto; il percorso ridotto resta a 16 MiB.

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
del numero di draw del programma. Il percorso canonico usa ora 96 MiB
complessivi e 16 MiB per PCS D34/D35, giustificati dal conteggio sotto.
I controlli del registro e del rifiuto AES a tre righe non percorrono la
promozione positiva; preparatore, prover, certificazione numerica e
schedule fisico restano aperti.

### Mandatory wire lower bound

I conteggi di codec nelle sezioni seguenti riguardano il **corpo della
risposta**. Escludono il bootstrap per sessione e quindi non sono upper
del certificato completo definito nel contratto aggiornato sotto.

L'encoding corrente impone, per una RNE con c bit di celle,
`7964 + 1176*c + 24*(funzioni + prodotti)` byte. I primi due termini
includono i nove campi per round, i tag, i prefissi u32 dei vettori e
l'intera prova P/S a otto livelli su c+3 bit. Le cardinalità sono imposte
da `rne::verify` e `range::tree_shape`, non scelte dal witness. Eliminare
l'ultimo termine dà un limite inferiore per **ogni** shift ammesso.

Il [censimento canonico](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical.rs)
conta 892 RNE e somme c=18.935/18.995/18.995 a O=0/150/300. Ne seguono
29.371.448/29.442.008/29.442.008 byte minimi. Sono esclusi header,
framing, sonde fresche, tutti gli altri operatori e ogni PCS. Il limite
non dipende dalla calibrazione, purché si mantengano schedule e codec
correnti. Per la sola fixture con esponenti zero (Pi=-14), il conteggio
RNE esatto è 30.604.688/30.675.248/30.675.248 byte; non è una misura su
checkpoint e non è il certificato completo.

Anche il solo istogramma del range W è obbligatorio e disgiunto dalle
RNE: `range::verify` impone 65.535 campi per l'alfabeto simmetrico 32767,
quindi `4 + 24*65535 = 1.572.844` byte di wire. Sommato al minimo RNE,
porta il limite inferiore a **30.944.292/31.014.852/31.014.852 byte**.
Questo è ancora un sottototale. Includendo le PCS, il conteggio esteso
sotto supera i 40 MB delle risposte successive per ogni calibrazione,
già prima del bootstrap. Il nuovo tetto iniziale di 130 MB non è escluso
dal solo corpo; il bootstrap resta da aggiungere.

Il precedente reader totale da 16.777.216 byte era incompatibile con
qualsiasi prova canonica completa. Il nuovo cap deriva dal conteggio
completo sotto, non da questo sottototale. Il percorso ridotto conserva
il proprio limite; entrambi i writer riservano i 26 byte di chiusura.

### Analytic envelope of the complete non-PCS body

`b12_native_wire_body_envelope` nel [diagnostico](../../scripts/c7_1_gemma_plan.py)
conta separatamente tutte le famiglie di frame della schedule nativa.
I conteggi fissi sono derivati dai descrittori pinned e dagli schemi `Wire`:
P0 e statistiche RMS, vettori/sonde RNE, GELU, gate-up, RoPE, QK/PV,
KV, softcap, massimo/lookup EXP30, range W/A, framing e chiusura.
Non somma i vecchi upper dei componenti con obblighi già condivisi.

Per le RNE usa il minimo già verificato e l'upper di 38 funzioni +39 prodotti
per record. Per i due GKR congiunti usa i guard nativi: al più 128 livelli,
14 bit di indice e 29 bit di celle (27/28 per il ratio nei tre contesti).
Un livello costa `100 + 124*c + 200*b` byte; si aggiungono i prefissi,
il prodotto finale e la prova sulle funzioni byte a c+4 bit. Il lower
omette interamente i due GKR congiunti; l'upper li comprende entrambi.

| O | Lower corpo senza header/PCS | Upper corpo senza header/PCS | Lower della fixture scale zero/Pi=-14 |
|---:|---:|---:|---:|
| 0 | 33.977.809 | 37.329.009 | 35.211.049 |
| 150 | 34.075.911 | 37.443.943 | 35.309.151 |
| 300 | 34.075.941 | 37.443.973 | 35.309.181 |

L'header aggiunge `1321 + 720*slot + len(gamma_W) + len(gamma_A)` byte,
deducibili dal registro con prompt100/token150.

Il test `c71_b12_native_canonical_wire_body_geometry` confronta ora ogni
famiglia non-PCS con il vero `Wire::read/write`, usando i descrittori
canonici dei tre contesti. Verifica P0/statistiche, i vettori 410/482 RNE,
lookup, prodotti, QK/PV, KV, EXP30 e range, senza allargare la visibilità
dei campi privati. Le fixture usano valori nulli e, per i due GKR, il
rettangolo massimo di forma; non sono prove valide o circuiti calibrati.
Il corpo con RNE selezionate e GKR massimi conta
36.913.833/37.028.767/37.028.797 byte; sostituendo le RNE con il loro
upper si ritrovano gli upper della tabella. Framing e chiusura sono
ora verificati anche sulla concatenazione sintetica completa descritta sotto.

### Canonical PCS wire accounting

`b12_native_linear_pcs_wire` riusa le geometrie PCS selezionate e conta
lo schema `codec::encode_linear`, senza il vecchio header matrix. Comprende
trasferimenti MAC e chiusura, sumcheck claimless, commitment e OOD, claim
base, messaggio/randomness aperti, tutte le maschere, valori interrogati,
sali e prefissi dei multiproof. I 12 batch hanno 29 maschere di fold e 11
di switch: 40 vettori da 2.560 campi, distribuiti in 23 gruppi. Le 59
aperture interrogano ciascuna 512 righe con quattro sali Fp per riga.

Il lower omette tutti gli hash dei fratelli Merkle: è un limite inferiore,
non una dimensione necessariamente raggiungibile. L'upper applica a ogni
apertura `c61_max_pruned_binary_siblings`, lo stesso limite del codec.

| PCS | Byte fissi senza fratelli Merkle | Upper byte fratelli | Upper totale |
|---|---:|---:|---:|
| W/D35 | 6.929.180 | 7.012.352 | 13.941.532 |
| A/D34 | 6.928.316 | 6.848.512 | 13.776.828 |

Il precedente cap di 8 MiB cadeva dentro entrambi gli intervalli. Il
nuovo cap D34/D35 di 16 MiB supera gli upper: il test Rust
`c71_b12_canonical_pcs_codec` serializza ora anche le frontiere massime,
fa roundtrip completo e respinge conteggi oltre la frontiera e input
oltre il cap. I byte fissi rimangono 6.929.180/6.928.316.
Sono forme sintattiche con radici/valori/hash nulli,
non PCS crittografiche valide né frontiere di prove reali.
Il primo confronto ha corretto il messaggio base: il codec usa le
32/64 celle **dopo** il fold finale, non le 128/256 precedenti. Il
conteggio Python precedente sovrastimava quindi A/W di 2.304/4.608 byte.

Sommando una PCS W e `slot+1` PCS A, corpo e header, si ottiene:

| O | Lower totale | Upper totale |
|---:|---:|---:|
| 0 | 47.841.180 | 65.053.244 |
| 150 | 54.868.318 | 78.945.726 |
| 300 | 61.797.384 | 92.723.304 |

Entrambi gli estremi includono ora i due vettori gamma da 2.277 byte
ciascuno, la cui lunghezza è verificata sulle configurazioni Rust D35/D34.
L'header completo è quindi `5875 + 720*slot` byte.
Il lower supera 40 MB nelle continuazioni per ogni calibrazione ammessa,
anche omettendo GKR congiunti e fratelli Merkle. L'upper qui deriva dagli
schemi, non dall'ipotesi che le PCS saturino il cap. Il rapporto conserva `credit:false`
e assenza di una misura su prove valide.

### Canonical transport limits and complete synthetic framing

`codec::max_bytes` seleziona 16 MiB solo per D34/D35 con feature B12;
gli altri profili conservano 8 MiB. Il gamma canonico dichiara `cap16MiB`,
aggiungendo un byte per profilo, e il digest pubblico del registro assorbe
il cap composto da 96 MiB. Header/FS canonici cambiano: nessuna compatibilità
con i precedenti header è promessa. Il percorso ridotto conserva il suo
codec e gamma. Sono limiti del parser, non nuovi parametri del protocollo
matematico: domini, query, maschere, ricette, MAC e risorse di security §6
restano invariati. Nessun trasferimento aggiuntivo del bound al Rust segue
da questa modifica, né ammissione dello schedule fisico.

Il test del corpo ora serializza tutti i 135/136/137 frame, PCS comprese,
attraverso il writer canonico e ricostruisce lo stesso digest col reader.
La fixture usa RNE a scale zero/Pi=-14, massimi di forma per i GKR e
frontiere PCS massime. Le dimensioni sono **64.638.068/78.530.550/92.308.128
byte**, con header sintetico della lunghezza canonica. Sono distinte
dall'upper per tutte le ricette sopra. Troncamento, riordino e appendice
sono respinti; il confine 96 MiB include il footer e un byte in più è
rifiutato senza avanzare il writer o FS. Il reader ridotto rifiuta queste
fixture per dimensione.

Il test non chiama VerifyResponse e non produce prove crittografiche
valide. `native_synthetic_full_framing_checked` distingue questo risultato
dalla serializzazione positiva del prover canonico, tuttora aperta.

### Experimental shared RNE byte proofs

La richiesta del proprietario del 2026-09-11 sposta il lavoro sulla riduzione
dei byte. La candidata `C71-RNE-joint-byte-experiment-v2` conserva le 892
riduzioni grado sette e differisce il loro controllo P/S. Il
[prototipo](../../rust/volta-pcs/src/c71_matrix/byte_function/batch.rs)
è compilato soltanto nei test; il verifier selezionato continua a eseguire
la schedule B12 e il suo lower di 47,84 MB resta valido per quella schedule.
Non sono cambiate semantica RNE, sorgenti W/A, parametri PCS o modello DV.

Ogni riduzione restituisce otto MAC aggregati **originali**, il punto di
cella e le otto tabelle pubbliche derivate da shift e beta FS. Nessuno di
questi MAC viene riautenticato. Dopo tutte le riduzioni, il caller ordina
le richieste secondo i produttori del compilatore canonico e forma gruppi
con al più 2^34 byte virtuali ciascuno. All'interno del gruppo, ordina i
blocchi per dimensione decrescente, stabilmente a parità, per ottenere
offset allineati senza riempire ogni richiesta fino alla dimensione massima.
Questa vista è una forma lineare su A, non un nuovo commitment o un nuovo
snapshot. Il primo screen con un solo gruppo ha fallito il limite D34:
la variante qui studiata usa esplicitamente più gruppi e ne paga i frame.

Per un gruppo, siano `r_j` i punti originali estesi con tre nuove sfide
di lane, `a_j` i corrispondenti aggregati MAC, e `off_j` gli offset pubblici.
Il transcript lega ordine, cardinalità, offset, root, profilo, tentativo,
identità, punti e tabelle prima della sfida di batching lambda. Gli
originali provengono dalle riduzioni già assorbite nello stesso FS.
Si costruisce la forma pubblica

```text
L(x) = sum_j lambda^j * selector(off_j,x_prefix) * eq(r_j,x_suffix).
target = sum_j lambda^j * a_j.
```

La versione 2 consuma direttamente quel target nel primo dei consueti
otto livelli GKR. Il suo polinomio è

```text
sum_x L(x) * (mu*(P_left(x)*Q_right(x) + P_right(x)*Q_left(x))
                   + Q_left(x)*Q_right(x)).
```

`mu` è la sfida del livello e il target iniziale è `mu*target`, perché
Q_top è zero sui byte ammessi. L è multilineare: il polinomio ha grado
al più tre in ogni variabile, come il livello GKR ordinario. Il terminale
usa `L(r)` calcolato pubblicamente dal verifier. Dopo la scelta del figlio,
gli altri sette livelli tornano ai pesi di uguaglianza ordinari. Si elimina
così il sumcheck quadratico separato e il suo MAC della root, senza una
nuova apertura o un nuovo target privato. La versione 1 con quel sumcheck
rimane documentata nei record immutabili precedenti.

I coefficienti Lagrange e il terminale byte rimangono quelli del batch:
ogni forma raw originale viene moltiplicata dal selettore del suo blocco,
con punto locale dato dal suffisso del punto congiunto. Tutti gli altri
obblighi di range, output e PCS A rimangono. `eq_scaled` costruisce il peso
partendo da lambda^j, senza un passaggio di moltiplicazione su tutte le
celle. Il riempimento dei byte fittizi riguarda solo gli spazi non usati;
i gruppi senza padding non eseguono quel passaggio.

Per una vista con `d` bit lo schema `Wire` ora costa
`5004 + 960*d` byte e consuma `169 + 32*d` correlazioni Fp3, inclusi gli
otto P/S e la maschera prodotti. Rispetto a v1 elimina `52+96*d` byte
e `1+3*d` righe per gruppo. Ogni gruppo conserva il frame da sei byte;
le 892 riduzioni grado sette, prodotti, liste e sonde restano nel conto.
Gli [esiti e i byte](evidence.md#shared-rne-byte-experiment) distinguono
prove piccole valide, forme canoniche sintetiche e proiezione completa.

**Obblighi prima della selezione.** `Mac.Valid.add/smul/sum` in
[`Mac.lean`](../../lean/VoltaZk/Mac.lean) giustificano le combinazioni degli
originali con i segni nativi; i lemmi di simulazione di
[`BlindSumcheck.lean`](../../lean/VoltaZk/BlindSumcheck.lean) riguardano
correzioni/residui sotto le proprie premesse. Non sono una prova Lean
del nuovo batch. Occorre ricomporre soundness FS sui veri prefissi
(batch lambda di grado al più `gruppo-1`, lane, primo livello cubico
con peso L e alberi condivisi), simulazione congiunta/NoPeek e risorse del riduttore.
Il codice legge valori prima delle righe e usa una maschera prodotti
fresca per gruppo, ma il test finito non scarica quei teoremi generali.
Gli 82,93/91,02 bit di B12 **non sono attribuiti alla candidata**.

Occorrono inoltre routing canonico degli originali, nuovo profilo/ordine
dei frame, riserve e verifica composta del certificato. Gli endpoint raw
passano da 892 a uno per gruppo, ma ciascuna forma sorgente resta nel
batch PCS; le aperture W/vecchie A/A e i loro byte restano presenti.
Il test limita il prover denso a `d<=9`; a D34 controlla soltanto
metadati e codec. La materializzazione contemporanea dell'albero richiede
`256*2^d` foglie: non è uno schedule fisico ammesso e non si avvia localmente.
Calibrazione, hardware e completa accettazione canonica rimangono separati.

## Resource and measurement contract

### Owner-authorized PCS/state experiment

**Steering del proprietario del 2026-09-12: 130/40 MB e ripiego analitico.**
Il tetto iniziale di 130.000.000 sostituisce quello di 70.000.000 byte;
le successive restano a 40.000.000, senza incremento cumulativo.
Se non emerge una soluzione praticabile per le continuazioni da 40 MB,
il proprietario autorizza la conclusione della parte proof-size anche con
i lower del corpo **47.841.180 / 54.868.318 / 61.797.384 byte** a O=0/150/300.
Questa deroga ammette un esito analitico: i lower omettono GKR congiunti e
fratelli Merkle e non diventano né upper né prove prodotte. La prima proof
include ancora il bootstrap entro 130 MB. PCS streaming, endpoint MAC
privati, arena e <=65 s restano requisiti del goal completo. Dal 2026-09-13
quattro letture W sono solo un obiettivo di ottimizzazione: più letture
sono autorizzate nello screen locale se tutti i costi restano espliciti.
Per «prova» si intende il **certificato completo**, coerentemente con
[C4.1](../c4.1-seed-streaming-fiat-shamir.md#objective-and-terminology).
Il corpo serializzato della risposta è una sua voce, non l'intero costo.
Indicando con R_j quel corpo e con B_j tutti gli altri byte necessari al
verifier e non già addebitati, valgono tetti assoluti in byte decimali:

```text
P_1 = R_1 + B_1 <= 130.000.000
P_j = R_j + B_j <= 40.000.000   per ogni 2 <= j <= C
```

B_1 include installazione/metadata trasmessi e tutto il bootstrap offline
per sessione ricevuto prima della prima risposta; B_j include eventuali
nuovi dati necessari. Si contano una volta i dati ricevuti, nuovamente i
riferimenti ritrasmessi. Il traffico nelle due direzioni resta esplicito;
almeno tutti i byte ricevuti dal verifier rientrano nei tetti. Non si
ammortizza B_1 su risposte future. **Lo 0,5–1,5% è sostituito**, non resta
un criterio aggiuntivo e il tetto non cresce col turno.

La capacità dello screen corrente è **C=3 tentativi 100+50, O=0/150/300,
450 token totali**, come il profilo matematico selezionato; non 4.096 o
una conversazione illimitata. Si verificano tutti e tre i contesti canonici.
Nessuna candidata ha dimostrato questi tetti entro tale capacità: tre
certificati validi su un grafo ridotto non costituiscono quella verifica.

La sola memoria aggiuntiva concessa è materiale globale del modello,
preparato/caricato una volta dal provider e riutilizzabile fra sessioni.
A modello fissato, contenuto e capacità non crescono né si rigenerano con
utenti/sessioni. Una sola sessione alla volta non autorizza cache esterne
A/KV/PCS specifiche della conversazione. Stato dinamico, HBM e arena restano
nei limiti ordinari sotto; nessuno spill dinamico è ammesso.

Il riuso di una trasformazione deterministica privata di W/Γ, senza nuova
vista esterna, può riusare la stessa funzione su input invariati; caricamento,
letture e copie si contano comunque. Questa osservazione non giustifica il
riuso del commitment salato B12: la simulazione di [security §5](security.md#5-simulatore-congiunto-e-nopeek)
trasla i pad sull'unione finita delle esposizioni di una nuova installazione.
Pad, sali con il loro budget di esposizioni, maschere e correlazioni monouso
non diventano materiale globale illimitatamente riutilizzabile. Nuove
sessioni richiedono casualità/righe fresche, domini separati e una composizione
same-W/ZK multi-sessione con risorse globali; i bound B12 non si trasferiscono.
Le sole identità MAC riusano i lemmi già elencati in security §6.

Per autorizzazione esplicita del proprietario, il contratto temporale passa
da 50 a 65 s, senza modifiche alle garanzie o agli altri cap.
Il prover completo deve impiegare **<=65 s per ogni risposta** della capacità
dichiarata sulla singola H100: generazione, witness, PCG, prova,
serializzazione, letture, scritture e trasferimenti necessari. Il caricamento
globale iniziale si registra una volta separatamente; setup per sessione e
risposta non si occultano in esso. Resta **lavoro totale non crescente su
ogni prefisso della stessa conversazione**, contro la baseline con stesso
modello, semantica, token e sicurezza: setup, precomputazione, replay e IO
inclusi. Un risparmio di byte o di correlazioni non dimostra quella proprietà.

Prima di implementare o approfondire: screen minimo di certificato, memoria
globale/dinamica, traffico per risposta, passaggi, banda effettiva motivata,
lavoro crittografico e tempo completo. Gli accessi esterni devono lasciare
un budget esplicito al calcolo; nessun overlap gratuito. Costi mancanti
restano ignoti (bound di ammissione infinito), non zero. Una candidata
incompatibile con tempo o memoria si scarta; per un costo decisivo ignoto
si svolge solo la verifica minima necessaria a chiarirlo. Lo screen non è
una misura completa né autorizza run pesanti/provider o spese.

**Esito dello [screen minimo](pcs-state-screen.md#screen-minimo-sotto-i-tetti-assoluti)
e del [confronto di nuove famiglie](construction-screen.md): nessuna
costruzione completa selezionabile.** PCG silent, LogVOLE, PCS con codici,
streaming, Akita e le nuove linee LogUp/Jindo/Dory non acquisiscono bound B12:
per le nuove composizioni
restano da istanziare campo, endpoint MAC privati, same-W/KV, ZK e risorse.
In particolare Akita lascia la ZK a lavoro futuro; non se ne adotta il
profilo pubblico per il modello privato. Il
[secondo screen](construction-screen.md#estensione-lookup-frazionari-e-pcs-hiding)
distingue evaluation hiding da apertura privata e conta i passaggi di
ricomputazione: anche la pista LogUp/Dory resta senza ponte di campo/MAC
e senza costo completo, non una sostituzione selezionata. Il bootstrap corrente supera
i tetti già per le sole correlazioni P/S RNE; le strutture dense superano
anche memoria e 65 s. La candidata W/A/KV da 10,31 TB resta fermata.
RNE v2, parametri PCS e conservazione dei dati iniziali mantengono soltanto
l'evidenza componente descritta nello screen; nessun port o ulteriore
ottimizzazione di queste costruzioni è il prossimo passo. Una nuova linea
deve risolvere sia il costo delle correlazioni fresche sia quello dei
consumer/PCS dinamici prima di essere selezionata.

Il [confronto mirato Akita–Shout/LogUp–Dory](construction-screen.md#confronto-mirato-akita-shout-e-logup-dory)
non seleziona una composizione. Shout negli originali DV resta un contributo
strutturale possibile, ma il suo screen minimo è ora completo abbastanza
da escludere i port letterali disponibili.
Lo [screen dei costi residui](construction-screen.md#shout-con-endpoint-originali-screen-dei-costi-residui)
respinge anche la sostituzione dei soli P/S con witness virtuale: conserva
bootstrap e range W incompatibili. Restano indimostrati adapter di
tabelle/pesi, apertura privata del one-hot e riuso multi-sessione.
Nessun lemma B12 copre queste nuove relazioni. Akita non offre Fp3 nel
packing pubblicato, i profili di apertura da circa 128 bit non soddisfano
il bound FS richiesto a Q=2^64 e il confronto MAC a due chiavi non nasconde
il transcript ricorsivo. Un wrapper blind-GKR dovrebbe provare l'intero
verifier lattice e i norm check; non è un adapter finale. Dory richiede il
collegamento dell'intera valutazione fra campi, non soltanto tre scalari.
Nessuna di queste ipotesi è assunta vera per B12, né i layout densi respinti
vengono riaperti.

**Bootstrap fresco candidato sotto la premessa ora autorizzata.** Lo
[screen Dory alimentato da B11](construction-screen.md#bootstrap-fresco-dory-alimentato-da-b11)
conta `t*(h+4)+3` seed sVOLE Fp/Fp3 nella variante con guard e check per
blocco, una riga base ciascuno. Con 130 MB
il solo COPE iniziale non respinge più le tre geometrie pubblicate;
la capacità di riferimento B12 rientra soltanto in LPN3. Non è un'ammissione
del certificato completo o della sicurezza EA-LPN-SL. F_Rand ha ora una
realizzazione ROM condizionale commit/response/open con abort e wire
completo; la prima candidata F_EQ vettoriale è respinta perché rivela i
residui di blocco sul mismatch. Il trasferimento compositivo, i codec nativi e il
cGGM su Fp3 richiedono ancora riduzioni malevole e risorse concrete.
AES-256/B11 non scaricano queste premesse.
L'ipotesi EA-LPN-SL-reg* è autorizzata nel trust model esteso sopra;
non modifica retroattivamente la dimostrazione B12 v1. Anche un bootstrap
idoneo lascia aperti range/PCS entro arena e il legame privato one-hot/originali.
Il [lemma candidato sui check per blocco](construction-screen.md#check-per-blocco-compatibilita-con-il-leakage-dichiarato)
fornisce `t*binom(N/t,2)/|Fp3|` soltanto con hash lineari fresche dopo
i vettori fissati, tre maschere per blocco e un unico AND finale. Non
realizza EA-LPN-SL o il cGGM: il teorema B12 rimane invariato.
Con il seed Fp9 la variante LPN3 rilassata conserva 13,78 MB di margine parziale;
con il resto del corpo/PCS B12 invariato è respinta già per byte ricevuti.
Il [guard dei cammini](construction-screen.md#guard-dei-cammini-prima-delle-correzioni-cggm)
verifica sui MAC originali `gamma*(gamma-beta)=0` per tutte le t*h
coordinate, in un solo batch prima di inviare c. Conserva beta uniforme,
zero incluso; con beta nonzero estrae un cammino binario, mentre con zero
simula c senza Delta. Lo screen large-field usa il profilo regolare
nonzero `t=675,h=19,ell=11`, N=353.894.400 e capacità 70.778.880; il
receiver invia la correzione autenticata del payload. Table 2 non assegna
128 bit concreti a Goldilocks e il bias Fourier mostra che dimezzare t non
è una riduzione: EA-LPN-SL-reg* è assunta con il bound autorizzato sopra;
beta onesti sono campionati
esattamente in Fp* senza abort osservabile.
Il bound ideale è `(t*h+1)/|Fp3|`; anche il fattore Q*=2^74 lascia
104,35 bit. Il guard elimina i due controesempi
identificati e sostituisce il precheck dell'inverso; NoPeek, FS e la
composizione B11→Dory richiedono ancora una formalizzazione completa.
La [candidata cGGM nel ROM separato per nodo](construction-screen.md#cggm-con-random-oracle-separato-per-nodo)
usa `left=H_D(x), right=x-H_D(x)` e nessuna permutazione/inversa. Dopo il
guard, una query al nodo nascosto determina un candidato Delta; il
simulatore costruisce `c` per livelli e programma soltanto la cella ROM
identificata da setup/blocco/livello/posizione. Il ramo beta zero resta
esatto. Il bound prudente per prequery è `Q_ROM/|Fp3|`, 118 bit con
`Q_ROM=2^74`; la somma condizionale nota resta 90,93 bit. Restano aperti
la formalizzazione della composizione sender con guard/split,
l'istanza SHAKE/codec e le risorse.
La [candidata seed Fp6→Fp3](construction-screen.md#seed-fp6-compressione-a-95-bit-nel-singolo-setup)
usa Wolverine con rho=95 e un solo setup: il bound condizionale seed
è 90,93 bit con gli envelope B12 conservati, senza cambiare ipotesi
AES/P-521 o risorse avversarie. Con 15.528 righe porta il
sottototale seed/payload Dory a **49,03 MB**. Non è un bootstrap completo
o una modifica al B11 selezionato: campo K6, suite e corrispondenza nativa
vanno implementati e verificati. La coin aggiunge 146 byte. Il confronto
dei digest ROM è respinto da un dizionario di `2^19` cammini. La PEQT
DDH/DLEQ da 823 byte è respinta perché l'estrazione via forking scende a
circa 59,5 bit; il malicious PSI compatto non fornisce due output con un
solo input corrotto. La candidata successiva usa un secondo seed Fp6 con
ruoli scambiati e le due chiavi MAC per aprire soltanto
`(Delta0+Delta1)*(wbar-vbar)` dopo autenticazione e coin fresche:
**12.815.274 byte**, incluso l'aggiornamento agli header nativi F_EQ/coin,
senza nuova ipotesi gruppo. Con l'upper B12 corrente
del primo corpo il parziale, incluso il framing guard/split nativo,
è **126.894.610 byte**, sotto 130 MB. Resta
da integrare il setup nel run sotto EA-LPN-SL-reg* a T121/M93 autorizzata;
formalizzazione compositiva, semantica con abort, corpo completo e tempo
restano aperti. Non è
un'ammissione. La fonte Ring-LPN 2022/1035 sostiene soltanto la plausibilità
di rumore regolare e leakage statico contro gli attacchi censiti su una
diversa famiglia large-field; non assegna sicurezza alla geometria corrente.

Lo screen successivo usa questo bootstrap soltanto come candidata
condizionale. Per K=256,d=1, Shout costa almeno `4T` prodotti, 96,57 miliardi
nel caso maggiore. Il one-hot corrispondente ha oltre 6,18 mila miliardi di
bit; l'apertura Akita è lineare nella lunghezza e il massimo pubblicato è
`2^35` bit. Range W può essere promosso una volta per la stessa `C_W`, ma
un product-sumcheck a memoria sublineare richiede circa sei visite,
ora ammesse in principio ma da prezzare nel tempo completo. Una candidata successiva
deve fornire insieme un'unica PCS sparse/streaming privata, il wrapper
Fp3–MAC e un upper completo <=65 s; nessun componente censito lo fa.

Lo [screen dopo l'autorizzazione](construction-screen.md#screen-dopo-lautorizzazione-ea-lpn-e-ripiego-sui-byte)
verifica capacità e byte sul run intero e registra il ripiego analitico
autorizzato. Il replay RS per coset con buffer di righe complete richiede
almeno 683 scansioni W nella costruzione esaminata. Un sumcheck lineare
prefix-first in due letture conserva invece lavoro rank×N; troncare i
supporti prima dei fold è errato. La variante suffix-first conserva invece
i selettori nella contrazione e ripristina il punto originale alla PCS:
due letture, 2.898.788.352 byte di array nel censimento pubblico e circa
314,5 miliardi di aggiornamenti dei due passaggi, esclusi PCS/range/folding.
È una candidata del solo riduttore W, con refinement del transcript ancora
aperto, non una schedule ammessa. Gli esiti negativi sono circoscritti alle
implementazioni esaminate, non lower universali sulle PCS streaming.

### Selected reference

Il port scalare `c71_gkr_main_cell_fused` è ora escluso dal requisito a
65 s per O=300: il solo EXP30 a frazione 14 ha lower 67,103981 s sotto
132 SM, clock ≤2 GHz e ≤64 risultati scalar INT-multiply/ciclo/SM applicati
agli `IMAD.WIDE.U32` emessi. Il mapping censito enumera una volta ogni
coppia programma/cella pubblicamente supportata, per livello e round, e
tutti i gate del programma; input già foldati sono concessi gratuitamente.
Il [certificato dei cammini compilati](preflight.md#no-go-del-main-cell-scalare-fuso),
conservato nel [record pulito](evidence.md#integrated-positive-and-scalar-main-cell-no-go),
prova almeno 24 risultati per prodotto Fp3 censito. Non è un lower per
Tensor Core/packing, nuove fattorizzazioni, specializzazioni dei primi
round o altro codice compilato: tali varianti devono ridurre davvero il
lavoro o cambiare la risorsa aritmetica e conservare transcript/endpoints.
Non si indebolisce il requisito temporale o crittografico per ammettere
il backend respinto.

Lo [screen delle due alternative EXP30](preflight.md#due-alternative-strutturali-exp30)
separa una sostituzione di protocollo da una diversa valutazione dello
stesso prover. La prova dedicata tramite residuo e range non è selezionata:
richiede nuove forme/slack/MAC e un nuovo transcript, con soundness e
simulazione da comporre. Gli endpoint E/Z/Pi originali e la causalità non
possono essere sostituiti da un solo istogramma D/E.

La candidata locale conserva invece circuito, ordine MSB, quattro
coefficienti per round e autenticazioni. Accumula pattern Boolean in
istogrammi **interni al prover**, pesati da Eq sulla posizione originale
e dal peso del gate; nessun conteggio privato viene aperto. La derivazione
algebrica vale sul campo originale, incluso il selettore del padding;
il primo check finito usa F97[u]/(u³−2). Il nuovo percorso nativo usa Fp3
originale e verifica parità wire/FS/MAC nel caso ridotto, con la stessa
continuazione range/PCS. NoPeek richiede che i pattern provengano solo dal getter
immutabile e che nessuna maschera MAC non consumata entri nei bin.
La fattorizzazione `H_g=sum_k Eq(k)*indicator`, poi `sum_g weight_g*H_g`,
non introduce nuovi messaggi, gradi o correlazioni. Il caso nativo a 32
celle verifica tutti i quattro round e il proseguimento, inclusi rifiuti.
L'esecuzione canonica, il refinement Lean e il picco completo restano
separati da questo controllo finito. Il cap locale dei payload istogrammi
è 1 GiB, controllato dalla forma pubblica prima dell'allocazione; non
sostituisce il contratto arena con 256 MiB di margine.
I bin conservano tre somme intere a 96 bit (u64 basso più u32 di riporto),
poi applicano la riduzione originale prima del peso Fp3. Ogni bin riceve
al massimo un contributo per posizione suffix: il guard pubblico
`suffix <= u32::MAX` esclude overflow. La cache privata E/Pi/Z contiene
solo byte originali causali, senza Snapshot/A completi né nuove aperture;
resta viva dal termine lookup all’ultimo consumer byte GKR. Le sfide,
i MAC e il transcript sono invariati; il riuso non elimina il replay Boolean.
Il replay packed usa ora un DAG di valutazione derivato solo dal circuito
pubblico: Copy diventa alias, identità Boolean e gate identici condividono
il risultato, sopravvivono solo gli antenati dei wire richiesti. I wire
originali sono ricostruiti nell’ordine originale prima degli istogrammi.
Queste identità si applicano ai bitplane Boolean prima del fold, **non**
ai polinomi dei gate dopo il fold. Circuito impegnato e transcript restano
invariati. La parità finita copre ogni livello EXP30 con maschere live
piene, parziali e vuote; il refinement Lean resta un obbligo distinto.
La candidata BMMA usa una rappresentazione per momenti degli stessi
quattro cubici: ogni limb canonico di Eq è decomposto in 64 bit e i
conteggi esatti sono ricomposti prima della riduzione originale Fp.
Non sostituisce il transcript né aggrega via istogrammi non posizionali:
Eq resta valutata sugli indici suffix originali; il rango compatto serve
solo al buffer. Il blocco canonico ha 15 righe vive e una riga ausiliaria
costante, che produce i margini lineari; quest’ultima non entra nel
selettore GKR originale. Copy usa Eq×wire, And/Xor usano X×(Y AND Eq_bit).
Nessun conteggio viene aperto. Per N<2^31 i contatori s32 e la successiva
ricostruzione unsigned a 96 bit sono esatti. Le sfide e i MAC non entrano
nelle scelte di layout. Il riferimento nativo con tile di un bit verifica gli stessi momenti
attraverso proof, FS, MAC e continuazione originale; non chiama i buffer
CUDA. Il backend selezionato rimane quello a istogrammi di cinque bit.
Il packing trasforma in-place ciascun tile dopo averne acquisito tutti i
512 B in shared memory; una fence separa producer e consumer. Dopo
l’ultimo batch, stage e piano replay sono liberati prima dei momenti Fp3;
i contatori restano vivi fino alla fence di riduzione. Il producer CUDA
consuma direttamente la cache originale E/Pi/Z: un CTA costruisce quattro
posizioni suffix e valuta il DAG pubblico in shared memory. Gli output
di uno stesso livello non sovrascrivono nessun input; gli slot scaduti
sono riusati soltanto dopo la barriera. La compattazione elimina solo
padding pubblico: Eq usa il suffix originale, ricostruito da layer/head/
query/key, con due tabelle di mezzi punti, anche per sfide 0/1. Il
raccordo privato dei 240 momenti canonici (225 quadratici, 15 lineari)
al prefisso nativo conserva i quattro cubici originali nel test ridotto.
Rifiuta dimensioni e codifiche Fp3 non canoniche; non è un messaggio
del transcript. Il compiler pubblico si prepara prima della risposta; i trasferimenti dei
piani per livello sono conteggiati nella prova. Il port integrato,
il refinement e l’esecuzione CUDA restano da verificare.

Il port letterale della fraction tree finale byte conserva ancora
`255*2^view_bits-8` coppie di coefficienti. Il kernel compilato a sei
prodotti base/Fp3 esegue 525 risultati IMAD.WIDE.U32 register-register per
coppia attiva. Sotto le condizioni esplicite del
[preflight](preflight.md#original-byte-tree-coefficient-screen), la sua
somma seriale con range/commit/prime aperture supera 65 s a O=150/300,
anche concedendo gratis inferenza, tutti i producer e il resto. Questa
linea è NO-GO senza H100; la condizione di riapertura è una riduzione del
lavoro o un mapping aritmetico diverso con nuovo screen. Il bound non si
trasferisce a una fattorizzazione della tree.

La [contrazione candidata](preflight.md#original-byte-node-contraction)
usa il grado delle funzioni del byte e il selettore originale dei nodi.
Al livello h ogni figlio ha numeratore di grado ≤D−1 e denominatore di
grado D, D=2^(7−h). La forma quadratica pubblica dei figli ha una base di
dimensione al più min(4·2^h,D+1). La diagonalizzazione per congruenza in
caratteristica dispari conserva anche matrici singolari e pivot fuori
diagonale; non richiede radici quadrate. I ranghi massimi degli otto
livelli sono [4,8,16,17,9,5,3,2], somma 64. Si foldano le funzioni dei
byte originali, mai la funzione del byte già foldato. Il selettore dei
nodi e lambda sono quelli già disponibili all'inizio del livello.

Le direzioni eliminate dalla forma possono servire ai quattro claim
terminali. Un nuovo replay privato dei byte, pesato con Eq del punto
cella appena completato, ricostruisce quindi tutti i figli originali;
seguono gli stessi round lane/nodo e MAC. Il padding strutturale del
frame GKR, il cui dominio è già completo, è byte zero: si separa la
baseline pubblica f(0) e si compatta soltanto il supporto pubblico di
f(byte)−f(0). Il caso generico byte-function con live_cells inferiore
al dominio ha invece numeratori nulli fuori live_cells e richiede una
baseline distinta; non è coperto da questo piano EXP30. Nessun pruning
dipende da zeri privati. Istogrammi e stati contratti restano privati,
senza nuovi messaggi, sfide, endpoint o assunzioni. Il test finito
controlla l'identità algebrica e il recupero terminale. L'oracolo Fp3
nativo riusa la LUT ByteTrees: per i livelli polinomiali usa la base di
Lagrange sui byte pubblici 0..D e verifica il grado su tutti i 256 byte.
Il raccordo nativo ridotto sostituisce soltanto coefficienti e quattro
figli terminali dentro lo stesso motore sourcewise: autenticazione,
tag residuali, FS, consumo MAC e split non sono duplicati. Il riferimento
riusa le valutazioni pubbliche e recupera i figli da istogrammi privati;
mantiene il fattore Eq del prefisso cella nei round lane/nodo. Nel caller
EXP30 a pattern è selezionato per domini completi ≤128 celle, con parità
proof/FS/MAC e positivo integrato lookup/GKR/WHIR. Domini ragged sono
respinti dall'entry point contratto prima di consumare righe o sfide.
Le LUT e gli stati conservano ora coppie f(byte), d·f(byte), con d
pubblico per il livello: foldare entrambi conserva d·fold(f), anche per
d=0, senza inverse o nuove sfide. I coefficienti richiedono tre prodotti
Fp3 per feature; il fattore Eq dell’asse corrente è applicato dopo la
somma globale dei tre coefficienti quadratici. Baseline e endpoint
restano quelli originali. Le due fold disgiunte e il lavoro di
prepesatura sono contati; il massimo EXP30 sale a 4.964.490.752 B a O=300,
sotto il massimo globale noto. Il backend CUDA a slot fissi conserva
i ranghi massimi anche quando una direzione pubblica è nulla. Lo
[screen compilato](preflight.md#original-byte-node-contraction) esclude
la prima implementazione con BMMA a O=300; non la contrazione
algebrica. Le primitive carry/borrow successive mantengono rappresentanti
canonici e campo originale. Lo screen ricontato sostituisce il costo range,
ricertifica la coda main e riapre il lower parziale: non trasferisce il
NO-GO al nuovo binario, né dichiara completo il ledger. I test host non
sono esecuzione delle istruzioni PTX; quel controllo resta nel futuro
esperimento autorizzato. Il proprietario ha scelto Γ calibrato del modello
reale per l'esperimento e ha confermato che è da calibrare sul workload C7.1
fissato a O=0/150/300, senza certificazione di qualità generale. Il profilo RMS
a scale zero resta sintetico; prima della chiusura del ledger occorre
produrre l'artefatto reale e validarlo attraverso il
[raccordo esistente](preflight.md#real-calibrated-gamma). La preparazione
offline di Γ precede installazione/bootstrap; non consente di adattare
scale, tabelle o circuiti durante una risposta certificata.

Il [dispatcher numerico per righe](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_prepare.rs)
usa i produttori del DAG canonico e le ricette possedute dal compilatore.
Riusa gli helper interi RMS/RNE/affine; restituisce righe nelle sorgenti
originali e visite agli istogrammi, senza FS, MAC o correlazioni in input.
Le tabelle devono essere già certificate dal profilo pubblico: i controlli
di forma del dispatcher non le certificano. Il driver causale per token
segue l'ordine del DAG, emette ogni bundle di righe al consumer e aggiorna
il token successivo solo dopo il successo di tutti i consumer del token.
Le decisioni usano le righe 99–148; il token 149 completa KV senza un'altra
decisione. Lo [storage del trial offline](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_calibration.rs)
collega i getter alle righe vive, conserva KV corrente in i16 e richiede il
KV precedente a un getter esterno causale. Rilascia dopo l'ultimo consumer
anche quando lo step non ha righe attive; accumula istogrammi e min/max
privati, senza Snapshot o A completi. Il lettore W usa `Read + Seek` e una
cache di riga sul packed già validato; lunghezza/codec non certificano hash
o identità del checkpoint. L'ingest offline può ora derivare gli esponenti
W con il worker BF16 nativo a un solo buffer per tensore, usando gli stessi
byte sottoposti a SHA-256 dal parent e pubblicazione atomica del packed.
Il test su shard piccoli non certifica provenienza o calibrazione di un
checkpoint reale. L'errore rende il trial inutilizzabile e non
pubblica il token parziale. La chiusura richiede tutti i 150 token e la
copertura di ogni sorgente originale, inclusi padding e istogrammi.
Il controller offline a tre trial riusa il registro pubblico compilato e
lo stesso reader W; il KV passa al trial successivo solo dopo copertura
completa, per movimento delle righe. Il wrapper da file genera le tabelle
con il riferimento certificato e verifica l'hash del packed contro il
report d'ingest. La sola CLI Rust non certifica quei due input. I test
eseguono sottografi, input pubblici e handoff KV con dati sintetici.
L'[inizializzatore A](../../scripts/c71_activation_pilot.py) usa una proiezione
del DAG nativo sui 1.435 ID semantici, W packed dequantizzato e KV causale
floating nei tre contesti. Propone esponenti da estremi osservati con un
bit di margine, mantenendo embedding legato a W e Pi a −14. RMS, GELU e
softmax floating sono approssimazioni preparatorie, non ricette intere
certificate o equivalenza BF16. Γ diventa utilizzabile solo dopo replay
intero completo positivo e congelamento; eventuali nuove scale invalidano
le tracce precedenti. Il [piano offline](preflight.md#real-calibrated-gamma)
separa letture logiche, payload e costi fisici ancora ignoti; questo pilot
non aggiunge costi o operazioni alla risposta certificata. Input reale ed
esecuzione/validazione numerica completa restano aperti. Non è ancora Prepare canonico
completo o ammissione del runtime. Questo storage offline non sostituisce
l'arena della prova: payload e bundle in ingresso sono contati, workspace
interni dei producer e allocator non sono un picco fisico chiuso.
Il ledger candidato riusa il census RMS nativo e lo screen Python con
gli stessi 421 tripletti di esponenti: non sostituisce con scale zero un
Γ differente. Ricompila le riserve delle tre risposte sulle tabelle
certificate; installazione W e bootstrap restano fuori da quel subtotale.
Conteggi di sorgente, ricette valide e confronto finito non certificano
calibrazione, istruzioni H100 o risorse complete.
Il padding query interno ai rettangoli A conserva la relazione originale:
`D-32767=-32767`, `E=2^30`, `Z=Pi=0`, a differenza del padding zero esterno
al dominio delle sorgenti. Il getter fornisce queste costanti; ciascun
istogramma EXP30 riceve una volta `32*106*(O+150)` visite pubbliche all'entry
zero. I controlli finiti del dispatcher non scaricano un refinement Lean.

Nel riferimento ridotto il getter usa LUT prepesate di f(byte)−f(0),
batch da 16 coppie e checkpoint min(9,floor(cell_bits/2)). Il supporto
deriva dalle assegnazioni pubbliche del caller GKR, mai dai byte privati.
La baseline f(0) entra analiticamente in ogni cubico; i buffer retained
contengono solo le chiavi proiettate e i fold mantengono due stati
disgiunti. Il recupero terminale aggiunge a H[0] la massa del padding
pubblico e precede gli stessi claim originali. Il caller Softmax ora passa i descrittori a intervalli delle righe causali:
la proiezione del supporto non enumera il dominio prima del checkpoint.
Le 12 lane private occupano gli stati; le quattro lane pubbliche zero
restano nella baseline e nei figli terminali. Il recupero Eq usa due
fattori di dimensione circa sqrt(N), senza tabella completa. I conteggi
di supporto coincidono col ledger a ogni round a O=0/150/300. Il guard
della proof resta ≤128: esecuzione canonica, refinement Lean e costi
hardware restano aperti.
I contatori scalari non contano implicitamente
l'evaluatore sostitutivo: il ledger ridotto registra i round custom a
parte, senza presentarli come lavoro nullo o conteggio canonico completo.



Il lavoro locale segue il gate integrato del 2026-09-19: una prova ridotta
positiva con getter ordinato, lookup streaming, GKR sourcewise e WHIR,
transcript e MAC originali, seguita dal ledger congiunto e dal minimo
kernel fuso rappresentativo. Lookup/GKR/capacity accounting restano
congelati salvo errori da almeno 16 MiB di picco o 0,5 s; nuovi dettagli
ABI non sono un gate autonomo. I contatori del riferimento scalare non
sostituiscono il lavoro della schedule canonica a 512 replay.

Dal 2026-09-26 il goal operativo locale è «C7.1 pronto per il minimo
esperimento H100»: si chiude con i gate pre-spesa del preflight, non con
la dimostrazione anticipata del tempo GPU. Il target finale rimane
T_inference + T_proof_only = T_response_total ≤65 s. Replay e autenticazione
A/KV restano integralmente in T_proof_only. Nessun rilassamento di arena,
margine, privacy, endpoint o trust model deriva da questa distinzione.


| Voce | Riferimento da soddisfare; nessuna nuova misura |
|---|---:|
| Prover completo a modello residente | <=65 s per risposta nella capacità dichiarata |
| Certificato completo, bootstrap per sessione incluso | prima <=130.000.000 byte; successive <=40.000.000 |
| Verifier CPU locale, quattro core | 6,4–8,2 s |
| Caricamento modello per residenza | riferimento storico 19,186 s, distinto dal setup crittografico |
| Inferenza e prover sulla stessa H100 | picco globale <80.000.000.000 byte |
| Letture packed W per la prova, oltre all'inferenza | quattro come ottimizzazione; più letture ammesse entro memoria e tempo |
| Arena temporanea complessiva | 6.442.450.944 byte |
| W packed | 61.394.690.560 byte |
| Materiale modello persistente, W inclusi | ≤2,10× W packed =128.928.850.176 byte |

I tetti di certificato e prover sono requisiti dello steering, non allarmi.
Solo il materiale globale riutilizzabile può eccedere i 2,10× persistenti;
questa concessione non aumenta HBM o arena. Gli altri riferimenti non
autorizzano a indebolire privacy o soundness. Nessuno spill, seconda copia dei pesi o
codeword completo è ammesso nel riferimento. Il trattamento delle sorgenti
richiede `c_source*N + P(q,h)` con coefficienti uniformi indipendenti da q/N;
nessun `qN`, `N log q` o `N log N` si nasconde sotto GKR o witness.
La dimensione del circuito/token rimane una voce distinta del lavoro completo.
Le letture W per ricostruire il witness, anche rieseguendo il forward,
rientrano nel traffico e nel tempo della prova. Prima che l'output fissi il prefisso FS si
prepara solo ciò che non dipende dalle sfide successive; non si anticipa
il folding. La cache accettata resta valida preparando il successore,
senza una seconda cache completa o alias che sovrascrivano dati ancora vivi.
Il teorema denso con codeword W da 4 TiB e A da 2 TiB è fisicamente escluso.

La partizione temporale vigente è `T_response_total = T_inference +
T_proof_only <=65 s`. `T_inference` è la sola generazione nativa originale
del provider. Ogni ricostruzione/riesecuzione A/KV durante la prova resta
in `T_proof_only`, insieme a producer, PCG, prova, serializzazione/trasporto
e attese/verifica necessarie; FS non aggiunge round-trip di challenge online.
Il setup fresco di sessione è censito separatamente e addebitato una volta
al PCG della prima prova e ai prefissi completi. Il [ledger dei trace](preflight.md#trace-della-risposta-e-budget-separati)
assegna budget di obiettivo a ogni fase, separati dagli upper ignoti. Separare setup, caricamento, trasporto e verifica
non sottrae lavoro dipendente dalla risposta. I byte completi includono
framing, roots, salts, indici/path, coefficienti, correzioni, prodotti,
range/lookup/padding. Ogni record ha produttore, consumatore, cardinalità,
encoding, dominio e consumo VOLE; una correzione Fp3 generica costa 24 byte.
Contare una volta i byte offline già ricevuti, di nuovo i riferimenti ritrasmessi.
Un costo ignoto ha bound di ammissione infinito, non costo zero.

Il picco comprende ciò che coesiste: W, KV, modello/runtime, testimone,
alberi, staging, GKR/PCS/PCG, maschere, attivazioni, workspace e allocator.
L'arena comprende tutti i temporanei controllati dall'implementazione;
è un requisito progettuale per la coesistenza del carico sulla H100, non
memoria aggiuntiva agli 80 GB né il limite totale della GPU. Il nuovo
[screen integrato](construction-screen.md#schedule-integrato-liveness-range-e-pcs-privata)
conta 3.543.662.592 byte residui sottraendo gli array suffix-first prudenti;
dimostra inoltre il rilascio algebrico di C prima del secondo passaggio,
senza attribuire il margine a buffer PCS/range ancora non costruiti.
Lo [screen range a finestre private](construction-screen.md#range-con-finestre-gram-private)
conserva gli endpoint originali e riduce il range W da 56 a 26 visite;
i nuovi conteggi sono espressioni di campo e payload, non un upper di
tempo o un refinement Lean. Non introduce ipotesi ulteriori. Rimangono
da scaricare il reader integrato e la sua disciplina NoPeek, oltre a
PCS, A/KV e risorse complete prima dell'ammissione fisica.
Il [preflight](preflight.md) include destinazioni fold CUDA fuori posto,
cache PCS persistente dentro arena, A corrente e vecchie A, KV pendente e
oracoli WHIR successivi. FFT a blocchi e range compilano per sm_90;
questo è un controllo statico locale, non tempo o memoria GPU misurati.
Il replay completo della terza risposta è escluso sotto i ceiling dichiarati
di banda/cache: i lower parziali sono 52,885/61,369/70,033 s, prima del resto.
I primi due valori non escludono da soli il contratto vigente a 65 s. La
[variante di apertura per resti](construction-screen.md#aperture-per-resti-a-cap-fisso)
ha un cap fisso 2^21 e costo sorgente uniforme nel suo nucleo, con
cache h12 da 188.743.552 B e range cut11/m24 da 29 visite. L'identità
algebrica è verificata su casi finiti; non introduce nuovi endpoint o
assunzioni, né un nuovo teorema Lean. Restano da scaricare il refinement
su codec/sali/NoPeek, source-uniformity del commitment e della PCS completa,
i getter A/KV, gli stati folded e il port reale PCG. Il cap del reader
privato, i pad e l'assegnazione dei sali devono restare identici.
Lo [screen dominante](preflight.md#test-decisivo-sui-costi-dominanti)
respinge il getter full-A con MAC scalari (solo commit >=135,257 s sotto
ceiling espliciti). Range specializzato, FFT e prime aperture danno lower
parziali 32,722/36,085/39,685 s, non upper o impossibilità universali.
Separare payload e X^M*pad preserva il polinomio originario; il layout delle
colonne è a chunk contigui. I sottoalberi zero restano nella somma GKR;
cache/mul6 non autorizzano pruning del supporto. Getter i16 esatti e trie
PCG pubblico richiedono refinement, senza nuove assunzioni di sicurezza.
Il primo switch senza retention aggiunge 64/32 replay W/A; il guard
sumcheck denso resta chiuso. Il cap proposto getter 64 MiB e PCG output
32 B/riga non scaricano i costi ignoti di maschere/covettore/seed/allocator.
Il confronto con 90 s non modifica l'obiettivo autorizzato <=65 s.
I trace locali coprono indirizzi di 3.471 sorgenti A, liveness dei tensori
per producer, tutti gli stati/oracoli WHIR e PCG. Singleton iniziale e
covettore Eq+Pow permettono contrazione e generazione a blocchi, ancora
senza adapter nativo; il precompute reference finito non dimostra il
vincolo uniforme per l'intero lavoro. La retention A fino al base case
conserva il predecessore fino alla query e solo poi fa fold/fence:
574 pass A corrente, 36 per storica, più letture e fold degli stati retained.
Anche questa schedule a quattro GEMM ha lower parziale condizionale
50,170 s alla terza risposta, prima dell'inferenza: non esclude i 65 s
ora autorizzati, né dimostra un upper o un’ammissione fisica.
I reference codec SHAKE H/EAGen sono decisioni locali,
non un trasferimento della composizione o nuovi messaggi; contare il
sampler fail-closed e verificare il binding alla coin originale. Non si
attribuisce alcun nuovo credito Lean/NoPeek a questi check finiti.
KV originale i16 costa 901.120 B/token: il precedente 4.915.200 era invece
l'incremento delle sorgenti A di attenzione. Il picco globale noto corretto
W+KV450+arena è 68.242.645.504 B, sempre prima dei residenti ignoti.
La proposta di un solo buffer persistente KV per 450 token conta anche
la coda pendente; non autorizza temporanei fuori arena. I picchi globali
completi allocato/riservato sono ignoti. In assenza di tutti i contratti
di lavoro e servizio, l'upper analitico di tempo rimane +infinito.
Lo steering del 2026-09-18 distingue questo limite dal gate pre-spesa:
un upper H100 non è richiesto prima delle misure. Restano obbligatori
costruzione completa su input ridotti, conteggi completi, picco pianificato
con almeno 256 MiB liberi e lower congiunto <65 s. Soltanto dopo questi
controlli si propone il minimo microbenchmark delle fasi con rate ignoto,
con SHA pulita, harness/input, durata massima, costo e soglie GO/NO-GO.
La spesa richiede comunque autorizzazione esplicita successiva.
Il [piano di indirizzi con margine](preflight.md#picco-con-margine-operativo-contratto-a-65-s)
richiede 256 MiB inutilizzati dentro arena e 1 GiB globale. Il checker
nativo degli span non certifica allocazioni GPU, fence eseguite o scratch
ignoti. La variante A 2^21/1.024 replay è chiusa NO-GO; il solo percorso
attivo è A 2^22/512 replay, con S2 2^22, successori al massimo 2^23
e reader riusato nel commit. La capacità S1 completa resta riservata
fino all’ultimo consumer: il fold non libera capacità tramite `truncate`.
Il getter ordinato full-DAG-per-tessera e il lift del Snapshot denso sono
respinti per le rispettive condizioni esplicite; non ogni getter streaming.
Il [DAG condiviso per finestre](preflight.md#dag-condiviso-getter-ordinato-e-riuso-del-reader)
ora conserva 61 tagli di layer, **98.380.800 B per una sola generazione**,
senza Snapshot/A completi. Raw e output arrotondato restano distinti;
un raw richiesto forza il producer anche se il suo output è in checkpoint.
L'ordine Gram è quello MSB-first del range nativo, con gruppo
`[tail][prefisso già folded][nuova finestra][sottoalbero]`; le query iniziali
PCS usano finestre byte originali, consumabili high-to-low entro colonna.
Identità finite e conteggi del DAG non sono il refinement numerico/NoPeek
del getter o un censimento delle transazioni HBM reali.

La variante con 1.024 replay commit, FFT a batch intero e getter condiviso
ha lower parziale condizionale **65,481 s a O=300**: NO-GO per quella
schedule seriale. La candidata minima riusa lo slot reader/hash durante
il solo commit iniziale A, torna a coset 2^22/512 replay e mantiene S2 2^22.
Richiede scatter senza reader e hash salted direttamente nelle celle
del coset già consumate, prima di ripristinare lo slot dopo fence; roots
e seed persistenti non si spostano. Il riuso è un obbligo nativo ancora
aperto, non uno shrink assunto del workspace. Con finestre range 2 GiB e
query A 256 MiB il massimo nominato è **6.166.153.984 B**, coda libera
**276.296.960 B**: restano appena **7.861.504 B** oltre il margine obbligatorio
di 256 MiB. Qualunque scratch non assorbito negli slot va aggiunto prima
di dichiarare fit fisico. I lower parziali con 512 replay sono
47,498/51,975/56,751 s includendo la lettura hash separata, ma escludono
ancora lavoro positivo e non sono upper.
Il budget candidato separa 1,5 s inferenza e 63,5 s prova, sempre 65 s
totali; replay e autenticazione restano interamente nella prova.
Il [getter numerico e hash ridotti](preflight.md#getter-numerico-e-hash-nativo-ridotti)
confrontano ora i byte del preparatore e le root native. Il primo riusa
operatori interi e conserva solo KV i16 fra risposte, con cut temporanei
legati a root/W/profilo/token originali. La sua forma numerica resta
quella ridotta: non dimostra ancora il port canonico o la composizione
con il prover streaming. L'hash conserva domain separator, endian e quattro
sali Fp canonici. Nell'ordine `c+Q*j` usa prescan naturale, offset effettivi
e frontier per j; non sostituisce il sampler con indirizzi `32*row`.
Il confronto root/sali è CPU, non un refinement CUDA/PCS completo o un
nuovo lemma Lean. Il nuovo lower parziale con lettura foglie separata è
47,498/51,975/56,751 s; hash compute, prescan, producer e backend ancora
esclusi impediscono di chiamarlo completo.
Producer GKR, adapter nativi PCS/PCG e workspace completi restano gate
locali. I soli service-rate non misurabili localmente potranno passare al
microbenchmark autorizzato dopo la chiusura dei gate di costruzione.
Il [replay WHIR ridotto](preflight.md#confine-nativo-whir-e-workspace-da-collegare)
chiude il confronto della catena D10 completa con `ObservedMmcs`, incluso
il binding pubblico delle aperture al FS C7.1: stessi
root, aperture, coin, codec, transcript e chiusura affine/base-case.
Il motore usa handle di replay perché l'interfaccia MMCS richiede riferimenti
alle matrici. Il percorso sourcewise rifiuta fallback densi, mantiene solo
Eq/Pow/sfide già fissate e libera ogni handle dopo l'ultimo consumer.
Il getter è ancora un riferimento CPU; razionale/remainder, port numerico
canonico e liveness fisica completa restano obblighi. Il cut della cache è
esplicito; l'ultimo coset riduce i digest in-place senza copia da 128 MiB.
H/EAGen hanno equivalenza Rust/Python e un controllo esaustivo ridotto
Acc/PuncAcc. Il riferimento ora riceve il primo split indipendente
`(k, offset-k)` della Fig. 3 Dory: derivare `k=H(offset)` non rappresentava
le coin del costruttore distribuito. Il vecchio controllo provava soltanto
l'identità additiva per quell'altro albero. La correzione riusa H dai
livelli successivi e non accredita il costruttore a ruoli separati.
Il [Seed6 reale ridotto](preflight.md#seed6-reale-streaming-e-workspace)
collega domini MR19 distinti, handshake direction-bound, COPE AES streaming,
check K6 e compressione. Non emette alpha dopo un check fallito. Il seed
principale richiede 17.553 righe (15.528 Dory + 2.025 F_EQ), quello inverso
2.025; il contesto nativo aggiunge 4 B al budget dei due seed. Capacità dei
Vec e rilasci anticipati sono censiti; burn durevole, FS globale, lifecycle
completo, picco fisico, CUDA e refinement Lean restano aperti.
Il [consumer guard ridotto](preflight.md#guard-originale-consumer-nativo)
usa ora l'algebra prodotti condivisa con range, negando solo Delta nel
passaggio bootstrap→MAC nativo. La ricetta di righe e il prefisso sono
fissati prima della sfida; l'API verifier fissa lambda prima di leggere la
prova. Il percorso reale ora deriva lambda con SHAKE256 dal prefisso
congelato contenente il binding sigillato; i callback prefissati restano
solo nei test algebrici. È il codec locale, non il transcript/lifecycle
globale. Il bound matematico candidato resta quello dello screen;
`prodKey_expand`/`prodKey_rlc_expand` in
[ProdSound](../../lean/VoltaZk/ProdSound.lean) giustificano l'identità algebrica,
non il refinement di questo codec. `prodBatch_sound_scalar` usa potenze
j+1; il consumer usa j: non si trasferisce il bound senza tale adattamento.
Nessun nuovo credito al teorema B12 o alla composizione EA-LPN. Il
[consumer F_EQ](preflight.md#f_eq-consumer-locale-dei-due-seed-opposti) verifica
localmente chosen-input e share a due chiavi con codec canonico e ordine
commit-before-open. L'exchange a due endpoint usa ora il framing bootstrap
esistente (tag u8, lunghezza u64 LE), controllato prima delle allocazioni;
nessun thread possiede entrambi gli stati F_EQ. I nove messaggi comprendono
correzioni, coin e share. È trasporto di questo consumer, non handshake
globale, canale autenticato, atomicità/fairness o journal durevole.
La riserva consuma il seed principale prima del guard:
copia solo la coda, cancella gli slot originali e conserva la capacità del
prefisso. F_EQ accetta esclusivamente code esatte, con binding originale.
Il [raccordo cGGM](preflight.md#guard-cggm-split-e-f_eq-a-ruoli-separati)
consuma il guard positivo e mantiene separati root/Delta sender da
cammino/beta/tag receiver. Il primo split è indipendente; con la convenzione
`d=s-r*beta` il puncture è il complemento dei bit r. I check split usano
le tre maschere originali per blocco, poi le sole code alimentano F_EQ.
F_EQ possiede root/chiavi pendenti e solo il successo restituisce la
capacità consumata dal [raccordo EA puntuale](preflight.md#ea-puntuale-dopo-accettazione-f_eq).
Questo componente test-only riusa Acc/PuncAcc ed EAGen, restituisce MAC
base uno alla volta e respinge riuso/esaurimento. Per ogni riga,
`m-k=Delta*sum_j(chi_j*sum_i(beta_i*[j>=i*2^h+alpha_i]))`:
l'accumulatore è globale, non separato per albero. Prefissi cumulativi
di beta/K(beta)/M(beta) includono i blocchi precedenti in tempo costante
per termine. Il packing nelle tre basi Fp3 conserva la stessa identità.
Il controllo reale produce sei righe e due MAC Fp3, confrontando anche
BAe su due blocchi; il precedente fixture t=1 non rilevava l'omissione.
Non è una proof positiva o il percorso canonico a trie batch.
Il seed EA pubblico è ora SHAKE256 del prefisso F_EQ e delle due aperture
verificate ordinate per ruolo, nel dominio `/accepted-EA/`; i blind da
32 B erano già committati prima delle aperture. Nessun nuovo messaggio o
override del seed nel costruttore di espansione. Nel ROM separato, la
coin locale richiede blind onesto fresco, commitment binding/hiding e
assenza di retry: il [ledger condizionale](preflight.md#seed-ea-dalle-aperture-f_eq)
aggiunge un envelope <2^-108, non un nuovo teorema Lean o un trasferimento
compositivo automatico. Rifiuti/withholding restano abort, non fairness;
binding globale, burn durevole e indipendenza nella riduzione completa
rimangono obblighi aperti, senza modificare le ipotesi primitive selezionate.
La catena ridotta passa con seed AES reali e rifiuta c/z alterati.
Questa è un'identità di correttezza verificata, non una nuova riduzione
malevola o un refinement Lean: si mantengono le premesse EA-LPN/cGGM dello
screen e i limiti formali del guard sopra. La
[coin nativa locale](preflight.md#coin-native-per-split-e-f_eq) realizza ora
commit/risposta/apertura per split e F_EQ. Il codec BLAKE3 lega nonce,
prefisso, fase, direzione, cardinalità e apertura; lo stream SHAKE256 lega
anche il prefisso successivo fissato prima dell'apertura. Questa scelta
instanzia i domini ROM condizionali dello screen, non aggiunge un teorema
Lean o una prova UC. L'argomento F_Rand resta subordinato a nonce fresco,
burn senza retry e ordine globale: il fixture non scarica il transcript
globale, trasporto o lifecycle. Il seal dei due seed è ora obbligatorio nel
[raccordo reale v02](preflight.md#seed6-seal-di-completamento): il binding
comprende il seal fresco dopo check/compressione e prima di qualsiasi
output. Si riusa il meccanismo B12 con un dominio wire Seed6 distinto;
il solo seal non impedisce rollback o retry senza il journal esterno.
Il [setup unico ridotto](preflight.md#setup-seed6-su-un-solo-canale) ora
esegue tutti questi scambi su un canale. Hash della geometria nel contesto
lega t/h/ell/capacità prima degli OT; il nonce cGGM deriva dai due binding
sigillati. Il receiver usa beta originale e cammini uniformi h-bit, non
valori privati prefissati dal fixture. Si conserva l'argomento algebrico
precedente, senza un nuovo teorema di composizione: autenticazione del
canale, non-rollback del journal e collegamento alla proof restano esterni.
Le coin dei test algebrici
restano distinte dalla catena che esegue il protocollo nativo.
 Il getter numerico ridotto
O=0/2/4 apre la root A originale con S1 condiviso allocato dopo le query
al predecessore. Il fold in-place dei successori segue il rilascio esplicito
dell’handle precedente; il riferimento CPU rifiuta riordini e getter obsoleti.
Il vecchio layout S3 2^24 supera l’arena se conta la capacità S1 reale; il
cap 2^23 conserva il massimo integrato nominato, pagando due letture S2
aggiuntive per A. Il merge FFT odd-log è censito separatamente: scatter PCS,
fence GPU e picco fisico completo restano aperti. I confronti finiti
non scaricano un nuovo refinement Lean. Restano NoPeek, endpoint e trust autorizzati.
Il [checkpoint RMS e il prover a memoria limitata](preflight.md#rms-checkpoint-originale-e-coefficienti-gkr-a-memoria-limitata)
conservano P/Y originali e S48 condiviso per riga: 2.023.511.878 B con
descrittori, nello slot range riusato prima di RNE. Il caller costruisce
il checkpoint dopo statistiche/prodotti e lo conserva fino al MAC byte.
Lookup pubblici sostituiscono gli assegnamenti densi; la serializzazione
streaming preserva l'unico frame FS originale, compreso il confine v1/v2.
Il prover collega replay Booleano, coefficienti MSB e riduzioni degli indici;
i confronti ridotti verificano byte, transcript e endpoint densi originali.
Il verifier deve calcolare massa viva e selettori senza Eq(N) o P*N.
La LUT pubblica dell'endpoint byte sostituisce gli alberi per cella,
conservando le otto discese e le medesime correzioni/challenge/MAC.
Il getter legge i quattro figli insieme; i pesi dei prefissi sono aggiornati
incrementalmente senza divisioni e senza saltare pesi nulli; un solo buffer
è riusato per tutte le richieste. Il replay
Boolean del GKR sostituisce solo i prodotti per bit con maschere dei limb
canonici, eseguendo comunque ogni addizione. La specializzazione interna
richiede righe prodotte da `Circuit::replay_layer`, non callback arbitrarie
con valori di campo; i controlli del transcript rimangono gli stessi.
Il ledger distingue rigenerazione, campo, getter e memoria; il fixture
pubblico a scale zero non è un profilo calibrato. Il percorso scalare
ridotto non ammette il canonico né chiude il workspace fisico completo.
Il [caller EXP30](preflight.md#exp30-massimo-con-un-solo-checkpoint) sostituisce
il massimo denso da 12,86/25,74 GB con un livello alla volta da
536.870.912 / 1.073.741.824 B; le assegnazioni sono lookup anche nel verifier.
Rilascia il checkpoint prima di lookup/GKR e conserva byte, ordine MSB e
endpoint del massimo. Il ledger conta le nuove scansioni D e il sumcheck.
Input/current/next del replay GKR sono riusati e liberati prima della LUT
byte. Il census nativo distingue capacità di programmi/prove/righe/triple,
transizioni dei pesi, Eq root/leaf e fasi. Le prove lookup restano vive fino
al consumer della risposta; prefissi prenotati e frame FS streaming eliminano
riallocazioni evitabili. Caller, allocator e workspace esterni restano
aperti. Il [lookup compatto](preflight.md#lookup-cache-originale-e-albero-tagliato)
conserva query/istogrammi originali e il cut superiore, rigenerando quattro
livelli senza modificare transcript o endpoint. EXP30 include tutto D/E,
anche il padding causale; la cache i32 non viene ristretta a i16. Albero,
cache e cut A hanno rilasci distinti dopo gli ultimi consumer. Il confronto
ridotto non è una prova del refinement canonico né del NoPeek del caller.
I probe CUDA standalone non danno lower al futuro kernel fuso e il vecchio
risparmio LSB-first non si applica al transcript MSB. Nessun nuovo lemma
Lean, variazione del trust o credito NoPeek deriva da questi controlli finiti.
Capacità riservata e occupazione logica sono distinte. Riuso e rilascio
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
e composizione: il requisito <=65 s vale su ogni risposta della capacità dichiarata sopra. Il layout KV
i16 usa 901.120 byte/token e 3.690.987.520 byte a capacità 4.096. La capacità
vuota non diventa arena aggiuntiva senza una prova di liveness/padding.
Size massima, lavoro e memoria vanno ricompilati per ogni carico; niente
medie o somme di sottototali incompatibili. Le letture oltre quattro sono ora autorizzate;
spill host e aritmetica ibrida restano [opzioni differite](decisions.md#deferred-requirements-and-options).

Le procedure e i limiti delle verifiche locali sono in
[build-and-test](../procedures/build-and-test.md). I test documentali non
richiedono build Rust/Lean; E2E pesanti e hardware richiedono l'autorizzazione
pertinente. Il port su grafi piccoli non autorizza allocazioni D34/D35,
benchmark Gemma o spesa. La produzione usa real/AES PCG e fallisce chiusa,
anche quando l'esecuzione GPU richiesta non è disponibile.
