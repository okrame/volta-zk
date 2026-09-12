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
**47,84/54,87/61,80 MB** a O=0/150/300: i tetti 35/40 MB restano superati
per ogni calibrazione, prima del bootstrap. Il limite
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

**Selezione estesa a nuove famiglie: nessuna costruzione completa supera
lo screen.** La riduzione della prova completa resta aperta. Il
[nuovo confronto](construction-screen.md) copre anche PCG silent, LogVOLE,
PCS con codici/reticoli e prover streaming. Akita con lookup Shout è la
pista strutturalmente più interessante, ma la ZK della PCS è ancora lavoro
futuro e manca il costo della composizione privata: non viene selezionata.
Lo steering del 2026-09-12 sostituisce lo 0,5–1,5% con **35.000.000 byte
alla prima risposta e 40.000.000 a ciascuna successiva**, senza crescita
del tetto. Valgono <=50 s per risposta sulla singola H100, IO incluso,
sola memoria extra globale riutilizzabile fra sessioni e lavoro totale non
crescente. Il [design](design.md#owner-authorized-pcsstate-experiment)
definisce contabilità completa e riuso; nessuna nuova spesa è autorizzata.

Lo [screen minimo](pcs-state-screen.md#screen-minimo-sotto-i-tetti-assoluti)
copre il profilo canonico a **tre tentativi 100+50, 450 token totali**.
Gli upper del solo corpo della risposta non includevano il bootstrap della
sessione. Con il bootstrap B12, le sole correlazioni P/S delle RNE
raggruppate richiedono al verifier almeno **90.989.568 / 119.107.584 /
119.107.584 byte**: già oltre i tetti, senza PCS e altri consumer.
Nemmeno distribuire quel costo sui tre turni rientrerebbe nei 115 MB totali.

La candidata densa W/A/KV da 10,31 TB resta esclusa per memoria dinamica.
Anche il percorso denso delle RNE condivise richiede oltre **169/176/176 s
di sole scritture** al picco teorico HBM, prima di letture, calcolo e PCS.
Sono limiti analitici della materializzazione, non tempi misurati né un
teorema d'impossibilità per altre costruzioni. Rendere globale soltanto W
non elimina né il bootstrap monouso né le strutture dinamiche.

Restano riutilizzabili, entro le rispettive premesse, la semantica e gli
endpoint originali, i controlli di [RNE condivise](evidence.md#shared-rne-byte-experiment)
e l'[identità byte/FS dei dati conservati](pcs-state-screen.md#dati-iniziali-conservati-uguaglianza-della-prova-e-lavoro-evitato).
I [tre certificati ridotti](pcs-state-screen.md#inferenza-completa-ridotta-con-rne-raggruppate)
non ricevono credito canonico, AES, multi-sessione o di lavoro totale.
B12 rimane selezionato, senza soddisfare i nuovi obiettivi.

Non si prosegue il port delle candidate respinte. Le nuove sostituzioni
dirette non rimuovono insieme i costi di correlazioni fresche, consumer e
PCS privata in memoria ordinaria. Il confronto distingue i rifiuti numerici
dalle composizioni con costi ancora ignoti; non afferma un'impossibilità
generale. Per riaprire servono tutti questi costi finiti, compreso il riuso
globale sicuro fra sessioni, senza occultare stato dinamico o setup.

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
