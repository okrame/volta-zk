# C7.1 — Goals and current status

Aggiornato al 2026-09-11. [Design](design.md) · [Security](security.md) ·
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
Il conteggio verificato dà un upper completo di 92,73 MB, entro i nuovi
cap. Il lower resta **47,84/54,87/61,80 MB** a O=0/150/300: preferenza
30 MB e allarme 35 MB restano superati per ogni calibrazione. Il limite
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

**La priorità del proprietario del 2026-09-11 è ridurre i byte completi dal
primo turno, riferimento 30 MB, e ottenere crescita costante/sublineare
con la storia, senza aumentare il lavoro totale del prover.** Setup,
precomputazione e replay contano; la sola risorsa aggiuntiva ammessa è
memoria persistente fuori H100. Sicurezza e confronto sulla stessa
conversazione sono condizioni di chiusura, tuttora aperte.

È stata implementata una
[candidata con P/S RNE condivisi](design.md#experimental-shared-rne-byte-proofs),
con [prove componenti valide e censimento canonico](evidence.md#shared-rne-byte-experiment).
Il risparmio proiettato è 25,13–25,19 MB per certificato; le RNE della
fixture a scale zero scendono a circa 5,48 MB. Non è più soltanto una
proposta di calibrazione. La candidata è test-only e non eredita i bound B12.

Il nuovo [screen PCS/stato](pcs-state-screen.md) verifica PCS valide piccole
con parametri ridotti e identifica il padding aggiunto dal primo batch
RNE. Il raggruppamento alternativo elimina quel padding, pagando 0,13–0,20 MB
in più. Con KV cumulativo e W a tre esposizioni, gli upper condizionali
della risposta sono **27,41 / 34,67 / 34,67 MB**: 2/3/3 PCS.
Questa variante resta limitata dalle tre esposizioni di W. Collegando anche
commitment W freschi al predecessore si proiettano **26,69 / 41,16 / 41,16 MB**,
con 2/4/4 PCS e due esposizioni per root. Sono schemi candidati, non un
minimo globale, un lifetime esteso ammesso o prove Gemma misurate.

La nuova [candidata con stato unico W/A/KV](pcs-state-screen.md#stato-unico-wakv-con-installazione-separata)
porta gli upper a **26,65 / 28,44 / 28,44 MB**, con due PCS per risposta:
W installato e S al primo turno, predecessore S e nuovo S nei successivi.
Il collegamento al W fissato prima del prompt resta incluso. Il dominio
S/D36 aumenta le celle dei sumcheck iniziali, ma riduce geometrie FFT e
termini delle query nei tre prefissi. Richiede circa 10,31 TB di payload
persistente prima delle promozioni successive, esclusi workspace e IO.
È ora la pista da verificare per il confronto congiunto byte/lavoro;
non è selezionabile dal dispatch e non ha un positivo canonico completo.

Il kernel PCS permette ora di conservare i dati iniziali del commitment:
il confronto D12 mantiene byte/FS identici ed elimina l'encode ripetuto,
senza rinnovare le esposizioni. Il wrapper C71 resta da collegare alla cache.
Lo screen conta anche setup e rinnovi e scopre una voce in aumento nella
candidata fold-6: i covettori delle query mantengono il lavoro t*M.
Il payload persistente proiettato di due W e due A è 8,66 TB prima della
promozione, esclusi workspace, allocator e trasferimenti; non è una misura.

**Nessuna variante soddisfa ancora tutte le condizioni verificate.** Il
prossimo lavoro è chiudere il confronto di lavoro completo, inclusi rinnovi
W, nuovi domini dei sumcheck iniziali, covettori delle query, sumcheck RNE
aggiunto e copia/link KV;
poi composizione ROM/ZK e routing canonico. Le geometrie FFT più piccole
non concedono da sole lavoro totale inferiore. B12 rimane selezionato.

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
del 2026-09-10 e del 2026-09-11 sulla riduzione dei byte.
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
