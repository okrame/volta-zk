# C7.1 — Goals and current status

Aggiornato al 2026-09-10. [Design](design.md) · [Security](security.md) ·
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

## Next goal

**Portare e verificare la corrispondenza nativa al protocollo composto.**
Riprendere l'harness a step esistente, con gli stessi identificatori e
criteri di completamento; questo riordino non introduce un nuovo milestone
né modifica gli script, i test o i loro campi di stato.

Il prossimo goal è concluso quando, su grafi piccoli:

1. Il preparatore produce lo snapshot immutabile e completa il KV dell'ultimo
   token, rispettando NoPeek e la semantica numerica del design.
2. Il verificatore possiede profilo, W e registro dei predecessori; esegue
   l'intera schedule obbligatoria, chiude tutti gli endpoint originali e
   promuove soltanto dopo il successo congiunto.
3. Il codec completo vincola ordine, cardinalità, contesto e framing nel
   medesimo FS; certificati incompleti, alterati o riferiti a un altro
   W/predecessore sono respinti senza promozione.
4. Controlli positivi e avversari documentano la corrispondenza, i consumi
   monouso e l'arresto definitivo; stato, design ed evidenza sono aggiornati
   insieme. Il successo di un componente isolato non conta come tale risultato.

Il riferimento preciso è [security §§2–3](security.md#2-preparatore-e-macchina-di-accettazione),
con le premesse runtime del [design](design.md#native-correspondence).
Non serve riaprire G2 né ripetere il goal matematico prima di questo port.

## Scope and authorization

Il lavoro locale pertinente è autorizzato. Si seguono le
[procedure di build e test](../procedures/build-and-test.md), con casi
piccoli e controlli mirati. Questo passaggio documentale non avvia il
prossimo goal tecnico: il punto di ripartenza sopra è pronto per il reset.

Restano fuori dal risultato acquisito: esecuzione Gemma completa, profilo
calibrato, provenienza dei pesi, codec misurato completo, schedule fisico,
prestazioni e produzione. Le materializzazioni dense del teorema sono
escluse dai limiti hardware del riferimento. Non segue alcuna autorizzazione
GPU/provider o di spesa. Rinnovi, recovery e riavvii rimangono accantonati.
La baseline B7 resta fermata; G2 e A5 restano non selezionati, con gli
[esiti circoscritti](decisions.md) conservati.

## Validation and maintenance

La chiusura matematica a `9e57199` ha 79 controlli Python mirati e il
self-check del diagnostico; sono evidenza algebrica/contabile, non un
nuovo teorema Lean o un E2E nativo. L'[evidence ledger](evidence.md)
registra comandi, ambito, provenienza e verifica di questo riordino.
Gli aggiornamenti successivi sostituiscono lo stato superato: niente
sottototali storici o diario dei componenti in questa pagina.
