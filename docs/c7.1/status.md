# C7.1 — Goals and current status

Aggiornato al 2026-09-12. [Design](design.md) · [Security](security.md) ·
[Evidence](evidence.md) · [Decisions](decisions.md) · [Indice](../README.md).
Questa pagina contiene stato, autorizzazione e prossimo lavoro; requisiti,
prove e risultati dei test hanno ciascuno la propria sede nei link sopra.

## Current result

**B12 è concluso come goal matematico condizionale.** Il
[protocollo composto](security.md) definisce preparatore, verificatore,
consumo dei MAC originali e promozione dello stato, e dimostra che tutta
l'inferenza accettata e la continuazione KV usano lo stesso W privato
estratto all'installazione. La simulazione congiunta conserva la privacy
anche sui prefissi interrotti. Non resta «integrazione corretta» fra le
ipotesi di quel teorema matematico.

I bound completi sono **82,9326056822 bit di soundness** e
**91,0227170067 bit di ZK** contro verifier malevolo, sotto le
[ipotesi primitive e di risorse dichiarate](design.md#assumptions-and-component-dependencies).
Il risultato riguarda una nuova installazione, un solo setup/key epoch,
tre tentativi 100+50 a O=0/150/300 e arresto definitivo su errore,
abort o esaurimento. Non è un'ammissione del verificatore nativo completo.

Il profilo pubblico numerico deve essere valido e posseduto dal verifier.
`C71-SOFTMAX-EXP30-v1` è già selezionato: non c'è una decisione sulla ricetta
ancora da chiedere. Calibrazione e qualità del checkpoint reale restano aperte.

## Native bounded result

**Il percorso nativo completo su un grafo piccolo è ora verificato nel
modello MAC ideale.** Il [runner interno](../../rust/volta-pcs/src/c71_matrix/gemma/native.rs)
collega Prepare, snapshot, tutti i produttori numerici/GKR, range/PCS,
certificato, VerifyResponse e promozione KV. Tre tentativi consecutivi
conservano un solo W installato e ricostruiscono lo stesso FS nei due ruoli.
Gli otto [test nativi](evidence.md#native-bounded-composition) coprono anche
framing, cardinalità, riordino, interruzioni, esaurimento, W e predecessore
alterati, inclusa la K dell'ultimo token già accettato. Un errore non promuove
lo snapshot pendente e termina il run.

È il controllo composto richiesto, anziché un insieme di ricevute componenti:
un layer, hidden/vocabolario 2, prompt 1 + generato 1, O=0/2/4, W/D10 e A/D12.
Il compilatore possiede 69 sorgenti A e tutte le relative ricette; i getter
leggono lo snapshot fissato prima delle sfide. Nessun logit, Pi, output RNE
o KV entra dal caller. Le restrizioni delle tabelle certificate sono
controllate contro il riferimento Python.

Questo non trasferisce automaticamente gli 82,93/91,02 bit al programma
Rust o al piccolo profilo. Restano distinti il teorema matematico completo,
l'esecuzione nativa nel modello MAC ideale e il port canonico/AES.

## Native port in progress

Il [compilatore causale canonico](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical.rs)
deriva 2.328 produttori per tutte le 3.471 sorgenti A, nei contesti
O=0/150/300. Controlla dipendenze, unicità e i dieci alias K/V pre-norm
globali; omissioni, duplicazioni e cicli sono respinti. È compilazione
pubblica dei descrittori pinned, non ancora esecuzione numerica del grafo
completo o verifica positiva delle prove sui 773 P0/421 RMS.

Il preparatore ridotto riusa ora le valutazioni intere
[RMS](../../rust/volta-pcs/src/c71_matrix/rms.rs) e
[RNE](../../rust/volta-pcs/src/c71_matrix/rne.rs) collegate ai descrittori
canonici e alla semantica dei circuiti. Gli shift negativi e grandi ammessi
dal verifier sono gestiti prima dell'encoding, con overflow reject.
Anche le [181 relazioni affini](../../rust/volta-pcs/src/c71_matrix/gemma/bytes/affine.rs)
ora condividono validazione di forma/codec/coefficienti fra Prepare e
verifier, con controllo i16 prima della valutazione intera.
I controlli locali usano righe sintetiche per 421 norme, 892 coppie RNE
e tutte le relazioni affini nei tre contesti;
restano da collegare gli altri produttori numerici e lo snapshot completo.
Non è ancora un'inferenza canonica.

Il [corpo del verifier canonico](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_verify.rs)
ora implementa la schedule completa di security §3 con ricette comuni,
MAC originali e PCS W/vecchie A/A corrente. I controlli locali coprono
riserva, contesto e prefisso pubblico fino al rifiuto di un P0 incompleto;
non un certificato canonico positivo. Il [wrapper interno](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_state.rs)
collega ora registro posseduto dal verifier, header locale e pool reale:
burn prima del decoding, promozione solo dopo verifica completa e journal.
Il profilo lega i corpi delle tabelle, senza certificarne i valori numerici.
Il controllo reale a tre righe copre il rifiuto per capacità insufficiente
senza promozione o riuso.

**Il limite di trasporto canonico è ora 96 MiB, con 16 MiB per PCS D34/D35.**
Il conteggio verificato dà un upper del corpo della risposta di 92,73 MB,
entro i cap tecnici di trasporto, non i tetti del goal. Il lower resta
**47,84/54,87/61,80 MB** a O=0/150/300: il corpo esclude già i 40 MB
delle continuazioni per ogni calibrazione. Il nuovo tetto iniziale di
130 MB richiede anche il bootstrap, escluso da questi conteggi. Il limite
del percorso ridotto resta 16 MiB totali e 8 MiB per PCS.
Le fixture canoniche complete da **64,64/78,53/92,31 MB** fanno roundtrip
nel framing nativo con lo stesso digest FS e rifiuto di troncamenti,
riordino e byte aggiunti. Sono prove nulle e massimi di forma, non
certificati validi: Prepare/prover e accettazione canonici restano aperti.
Il profilo pubblico lega i nuovi cap; non si riusano header canonici precedenti.

Il [collegamento AES/journal](../../rust/volta-pcs/src/c71_matrix/gemma/native/pool.rs)
ora alimenta il wrapper ridotto tramite riserve del pool reale, con segni
MAC nativi, confronto del registro e promozione dopo il journal. Gli
iteratori ideali sono confinati ai test. Il controllo reale a tre righe
verifica l'arresto per capacità insufficiente, senza pubblicare A né
promuovere KV. **Non è ancora un'esecuzione composta AES positiva.**

## Next goal

**Priorità immediata: bootstrap fresco compatto, prima di approfondire
Shout; nessuna candidata completa selezionabile.** L'ultima deroga del proprietario
porta il certificato completo a **130.000.000 byte alla prima risposta e
40.000.000 a ciascuna successiva**, bootstrap/installazione inclusi. Restano
≤50 s anche alla prima, sola memoria extra globale riusabile fra sessioni
e lavoro totale non crescente su ogni prefisso. Capacità esaminata:
**C=3 tentativi 100+50, O=0/150/300, 450 token**. Capacità che soddisfa
congiuntamente i requisiti: **nessuna**. Vale il
[contratto aggiornato](design.md#owner-authorized-pcsstate-experiment).

Il [nuovo screen dei costi residui](construction-screen.md#shout-con-endpoint-originali-screen-dei-costi-residui)
respinge la sostituzione dei soli P/S con Shout, anche se il nuovo consumer
riuscisse a stare nell'arena. RNE originali e contatori W conservano almeno
**9,05 GB di correzioni COPE nel bootstrap iniziale** per C=3. Il range W
conserva un **albero dinamico da 3,30 TB**, dipendente dalle sfide e quindi
non globale. Questi lower riguardano i componenti conservati, non tutte
le costruzioni Shout. Non si implementa né si ottimizza questa sostituzione.

La deroga a 130 MB rende valutabile il
[seed B11→Dory](construction-screen.md#bootstrap-fresco-dory-alimentato-da-b11),
ma non ne chiude la riduzione. Il nuovo
[lemma sui check per blocco](construction-screen.md#check-per-blocco-compatibilita-con-il-leakage-dichiarato)
risolve condizionalmente il collegamento alla forma cartesiana del
leakage LPN; il check congiunto della fonte non fornisce automaticamente
quel collegamento. Occorrono maschere distinte e **un solo esito AND**.
Il lemma presuppone coin fresche; il trasferimento FS con Q*=2^74
non conserva i 78 bit richiesti.

La [verifica del cammino finale non binario](construction-screen.md#cammino-finale-non-binario-check-e-recupero-della-chiave)
mostra che il check può accettare due foglie autenticate: quel caso
richiede estrazione, non abort presunto. Inoltre il port RPM con
**sigma=c*id, c in Fp diverso da 0,1, espone Delta con una query inversa**
ed è escluso; il risultato algebrico ha un controesempio finito riproducibile.
Il [caso beta=0](construction-screen.md#payload-zero-controllo-necessario-prima-delle-correzioni)
espone Delta anche nel ROM, prima del check: è escluso il port letterale
che lo ammette. La riparazione candidata prova beta*beta^(-1)=1 sui MAC
originali **prima di c**, riusando il batch prodotti. Con questo controllo
e quelli per blocco, il sottototale LPN3 diventa **121,49 MB** nelle due
direzioni, prima di corpo e voci mancanti. Conservando PCS/altro corpo
B12, il lower ricevuto è già **141,55 MB**: occorre cambiarli comunque.
Restano da provare la nuova distribuzione F*, il cGGM concreto con beta
nonzero e la simulazione malevola. EA-LPN-SL, F_Rand/F_EQ e costo completo
restano aperti. La
[verifica Half-Tree](construction-screen.md#realizzazione-cggm-cosa-trasferisce-half-tree)
esclude anche il trasferimento diretto del ramo pcGGM binario: l'hash
finale rompe le somme richieste dall'accumulo Dory. I cGGM nel ROM
pubblicati per commitment binari non danno già la simulazione DV.

Shout resta la priorità strutturale del [confronto](construction-screen.md)
per il minor conto aritmetico del consumer, subordinata al bootstrap.
Restano aperti il collegamento privato del one-hot ai byte e MAC originali,
range/PCS entro arena, disponibilità del witness, IO/replay e lavoro completo.
Akita–Shout e LogUp–Dory non sono composizioni selezionate; non hanno un
upper completo giustificato o una prova trasferibile dai bound B12.

Lo [screen precedente](pcs-state-screen.md#screen-minimo-sotto-i-tetti-assoluti)
resta negativo anche sotto 130/40 MB: non si riaprono le materializzazioni
RNE o le cache dinamiche W/A/KV. Semantica, originali e controlli delle
[RNE condivise](evidence.md#shared-rne-byte-experiment) restano riusabili
entro le proprie premesse; i tre certificati ridotti non acquisiscono
credito canonico, AES, multi-sessione, prestazioni o lavoro totale.
B12 rimane selezionato senza soddisfare il goal di riduzione.
Nessuna nuova spesa o esecuzione pesante è autorizzata.

Il precedente goal di estensione resta aperto e subordinato a questa
priorità: collegare Prepare/prover canonici al wrapper, conservando gli
originali e la compilazione numerica comune; verificare poi il percorso composto AES positivo.
Le sue 797.139 righe base sul grafo ridotto superano il perimetro dei
bootstrap locali e richiedono hardware autorizzato. La compilazione
causale non fornisce lo schedule fisico per D34/D35.
Non si ammettono per questo esito esecuzione Gemma completa, produzione,
un nuovo bound Rust o materializzazioni D34/D35.

L'harness conserva B12 e i campi di ammissione canonica;
`native_bounded_composition` distingue il risultato ridotto e
`native_canonical_producers` la compilazione senza witness. Il riferimento
resta [security §§2–3](security.md#2-preparatore-e-macchina-di-accettazione),
con i limiti del [design](design.md#native-correspondence).

## Scope and authorization

Il lavoro locale pertinente è autorizzato dalle richieste del proprietario
del 2026-09-10 e del 2026-09-11 sulla riduzione dei byte, ristrette dallo
steering del 2026-09-12 su memoria globale e fattibilità entro 50 s.
Si seguono le [procedure di build e test](../procedures/build-and-test.md):
build mirata con un job, test seriali limitati a 60 s/2 GiB e un worker Rayon.

Restano fuori dal risultato acquisito: esecuzione Gemma completa, profilo
calibrato, provenienza dei pesi, codec misurato completo, schedule fisico,
prestazioni e produzione. Le materializzazioni dense del teorema sono
escluse dai limiti hardware del riferimento. Non segue alcuna autorizzazione
GPU/provider o di spesa. Rinnovi, recovery e riavvii rimangono accantonati.
La baseline B7 resta fermata; G2 e A5 restano non selezionati, con gli
[esiti circoscritti](decisions.md) conservati.

## Validation and maintenance

La chiusura matematica a `9e57199` conserva i suoi 79 controlli Python.
L'[evidence ledger](evidence.md) registra separatamente i controlli del
nuovo percorso nativo e le regressioni. Nessun benchmark di produzione,
nuovo teorema Lean o E2E su checkpoint reale è attribuito a questi test.
Gli aggiornamenti successivi sostituiscono lo stato superato: niente
sottototali storici o diario dei componenti in questa pagina.
