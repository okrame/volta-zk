# C7.1 — design

[Specifiche](specs.md) · [Sicurezza](security.md) · [Test locali](local-tests.md) ·
[Test su RunPod](runpod-tests.md) · [Archivio](../c7.1-history/README.md)

## Obiettivo e relazione dimostrata

C7.1 dimostra a un verificatore designato l'inferenza intera di un modello
privato e la continuazione della sua memoria di attenzione, chiamata KV.
Tutte le risposte accettate devono usare gli stessi pesi W fissati
all'installazione. Il verificatore apprende i token pubblici e l'esito;
non riceve pesi, attivazioni o valori intermedi privati.

Il modello è la parte testuale di `google/gemma-4-31B`, con
[identità immutabile](specs.md#input-e-identità). La relazione usa la semantica
intera in [specs](specs.md#semantica-numerica): arrotondamento al più vicino
con pareggi al pari, rifiuto degli overflow e softmax `C71-SOFTMAX-EXP30-v1`.
Il nome `gemma31b` nei percorsi del codice identifica questo checkpoint.
Il commitment certifica i pesi installati; la loro provenienza e la qualità
del modello sono proprietà separate.

Un'esecuzione parte da KV vuoto e comprende al massimo tre tentativi.
Ogni tentativo contiene 100 token di prompt e 50 generati; i contesti
precedenti hanno quindi lunghezza O=0, 150, 300. Si certifica anche KV
dell'ultimo token emesso. Qualsiasi errore, interruzione o esaurimento
termina definitivamente l'esecuzione. Non sono previsti rinnovi,
riavvii, importazione di ricevute o prosecuzione dopo un rifiuto.

## Organizzazione del protocollo

Il parametro pubblico Γ fissa modello, scale, tabelle numeriche, disposizione
dei dati e ricette dei circuiti. Il verificatore lo valida e lo possiede
prima di installare W o predisporre correlazioni crittografiche.
La calibrazione deve riguardare i pesi reali e il workload fissato nei tre
contesti. Non è richiesta una certificazione generale della qualità.

L'installazione di W è indipendente dalla chiave del verificatore e dalla
sessione. Il setup crittografico predispone invece una capacità finita di
correlazioni monouso. Prima di ogni prova, il preparatore calcola e valida
tutti i valori privati senza leggere quelle correlazioni. La prova può
ricostruire valori, purché coincidano esattamente con quelli fissati.

Le verifiche matriciali, numeriche, di intervallo e della storia KV
confluiscono in aperture PCS sui valori autenticati originali. PCS indica
il commitment polinomiale e la sua prova di apertura; un nuovo MAC valido
su un valore diverso non chiude il requisito. Ogni risposta usa una PCS
di W, una per ogni A precedente e una per l'A corrente, dove A raccoglie
tutti gli ausiliari della risposta. Non esistono prove PCS per token.

Un unico transcript Fiat–Shamir determina le sfide della prova a partire
dai messaggi già fissati. Il verificatore ricostruisce contesto e storia
dal proprio registro. Brucia l'intera riserva prima dell'uso e promuove
la nuova A e KV solo dopo tutte le verifiche e la registrazione durevole
dell'accettazione. Un semplice ACK non promuove lo stato.

## Costruzione da implementare

Il percorso di implementazione conserva la relazione e l'ordine di verifica
B12, con W packed immutabile, lettura ordinata di A, ricostruzione per
finestre e PCS senza vettori sorgente completi. La configurazione delle
risorse usa 512 ricostruzioni per il commitment iniziale A, stato S1
trattenuto per A e apertura RS mediante resti di polinomi. I parametri e
gli obblighi di memoria sono in [specs](specs.md#pcs-e-ricostruzione-dei-valori).

Il generatore efficiente di correlazioni è il riferimento CPU Seed6,
abilitato esplicitamente da `c71-seed6-reference`, con la premessa
EA-LPN-SL-reg* autorizzata. Il teorema B12 sul bootstrap originario e
questa estensione hanno confini distinti: [security](security.md) espone
le ipotesi e ciò che resta da dimostrare. L'esecuzione di test Seed6
non trasferisce automaticamente i bound B12 al programma completo.

## Stato di implementazione e lavoro necessario

La prova canonica completa non è pronta per una misura. Il riferimento
di calibrazione è CPU, anche su un host H100. L'export completo e il
validatore strutturale della traccia di calibrazione sono disponibili.
La CLI esporta anche il piano pubblico esatto dei 13 tipi di operatore e
il wrapper ne valida DAG, riferimenti e layout W. Il driver indipendente
esegue quel piano a memoria limitata e la modalità `trace` richiede ora la
parità esatta di ogni frame prima della pubblicazione. I test locali coprono
tutti gli operatori e l'intera schedulazione canonica; manca l'esecuzione sui
pesi reali e il suo tempo completo non è misurato. Lo
[stato e l'ordine di lavoro](runpod-tests.md#stato-e-sequenza-operativa)
identificano componenti disponibili, implementazioni mancanti e passaggi
che richiedono autorizzazione. Il [contratto del confronto](specs.md#confronto-indipendente)
definisce cosa completare prima di ammettere Γ.
Il [readiness audit v6 di partenza](../../benchmarks/results/c71-h100-e2e-readiness-2026-10-03-fbd6141e7a1e.json)
registra `NOT_READY` per la prova E2E. Sono ora implementati il corpo del
prover canonico, gli snapshot/getter CPU con padding e istogrammi, il
trasporto del completamento e un eseguibile CPU esplicito per tre risposte
sullo stesso registro. Non sono ancora acquisiti certificati canonici
validi: il codice non conferisce readiness. Il runner registra ora fasi
wall e traffico effettivo, inclusa la distribuzione di Γ/tabelle/root e
le richieste. Il verificatore ricompila i dati ricevuti; installazione e
setup sono addebitati alla prima risposta. Questi strumenti non sono una
misura canonica acquisita né un conto completo di CPU/HBM. Il
[checkpoint della strumentazione](../c7.1-history/canonical-runner-measurements.md)
ne espone copertura e limiti, inclusa la separazione ancora aperta dei costi
di inferenza e preparazione. Il commitment iniziale A collega ora una
scansione causale completa per coset: geometria 2^22, quindi 512
ricostruzioni, senza callback scalare per ogni byte durante il commitment.
La geometria iniziale W usa gli stessi coset e 1.024 passaggi. La parità
è controllata soltanto su domini piccoli; nessuna esecuzione D34/D35.
Il [checkpoint del collegamento](../c7.1-history/canonical-initial-scan.md)
documenta la sostituzione del precedente cap 2^18 e le copie eliminate.
Le prime query A usano ora finestre originali fino a 256 MiB, condivise
fra colonne all'interno del batch, senza trattenere un buffer per ogni
root storico. L'output delle query non duplica più una matrice intera
durante la conversione dei limb. Il
[checkpoint delle query](../c7.1-history/canonical-query-windows.md)
distingue questo collegamento CPU dai limiti ancora aperti.
Lo stesso scanner alimenta ora il singleton PCS, i coset S1, l'OOD e
la rigenerazione di S1, accumulando contributi lineari dai byte originali
senza getter scalare per cella. Ogni passaggio resta separato dalle
barriere FS. Il coset extension usa direttamente limb base column-major,
senza matrici complete di conversione; il
[checkpoint delle riduzioni](../c7.1-history/canonical-residual-scan.md)
ne delimita la parità ridotta, non una misura canonica.
Il riferimento ora collega anche la geometria canonica degli stadi PCS:
S1 2^24, S2 2^22, successori al più 2^23. Il residuale supera il precedente
cap D16 con blocchi P/Q al più 2^21 e preparazione condivisa fra due fold,
rilasciata prima del commitment successivo. Il
[checkpoint degli stadi](../c7.1-history/canonical-pcs-stages.md)
separa supporto CPU delle shape, parità ridotta e validazione completa.
Il preparatore dispone anche del gather range in ordine
`[tail][prefisso folded][u Gram][sottoalbero]`, con selezione dei producer
per intersezione delle tessere e cap di 2 GiB. Il
[checkpoint del gather](../c7.1-history/canonical-range-gather.md)
è seguito dal [consumer range A](../c7.1-history/canonical-windowed-range.md):
il riferimento CPU collega canopy, Gram e retention allo stesso reader.
Il primo scan PCS conserva l'istogramma byte; il range non aggiunge uno
scan per ricostruirlo. D34 seleziona 26 passate dopo l'istogramma, ma non
è eseguito: la parità completa resta ridotta. Lo stesso motore ora serve
anche W signed, dal packed originale: cut=11/m24, 29 passate selezionate,
staging di 256 MiB e istogramma privato calcolato all'installazione.
Non ripristina il piano W cut=10/m25 escluso per memoria. Gli altri consumer
non convertiti mantengono il riferimento precedente. Mancano CUDA, conto completo dei
producer/arithmetic work, memoria simultanea e verifica canonica del range;
la riduzione delle rigenerazioni non è un tempo H100 o una nuova prova Lean.
Il bound di lavoro Eq/Pow dello screen rimane condizionale e non è
trasferito automaticamente a questa implementazione.
Il port CUDA del range dispone ora di kernel nativi per canopy, gruppi
Gram, retention, fold e coefficienti. Il relativo controllo host non
esegue i kernel; compilazione sm_90 e parità dell'algebra non sostituiscono
il collegamento Rust, gli owner residenti, il fencing prima dei MAC o la
verifica GPU, ancora da completare. La riduzione H con CAS, Eq per indice
e lo stack locale del kernel coefficienti richiedono contabilità e misura;
non ereditano il tempo o i conteggi dello screen storico.
Rimangono lavoro locale sui workspace dei resti/multipunto, sul range,
sui kernel densi, sul percorso CUDA e sulla contabilità fisica simultanea.
I percorsi PCS grandi non sono ancora eseguiti o misurati. Questi non sono
blocchi risolvibili soltanto procurandosi H100, né il collegamento CPU
costituisce il getter GPU completo entro i limiti dichiarati.
I dettagli e i limiti del riferimento sono nelle
[specifiche](specs.md#preparazione-e-prova-a-memoria-limitata). Il
[checkpoint di implementazione](../c7.1-history/canonical-reference-implementation.md)
conserva le decisioni e i fallimenti senza attribuire credito canonico. Il
[record del driver](../../benchmarks/results/c71-independent-driver-2026-10-02-645e855645d8.json)
chiude l'assenza dell'implementazione locale, ma non convalida i pesi reali
né chiude la finestra temporale della campagna di calibrazione.
Il [tentativo ridotto con pool reale](../../benchmarks/results/c71-real-two-attempts-2026-10-03-262e89febe2c.json)
ha completato una risposta e raggiunto il range A della seconda, ma è stato
terminato al limite locale di 60 s; non dimostra due promozioni sullo stesso
registro e non è stato mantenuto come test lento duplicato.
Il [controllo delle credenziali locali](../../benchmarks/results/c71-local-secret-permissions-2026-10-03-d14843b3e1fb.json)
ha inoltre corretto il `.env` ignorato a `0600` e aggiunto un preflight che
non carica né stampa valori segreti.
La campagna H100 ha anche un hard stop operativo: dal CLI v2.12.0 Runpod ha
rimosso le deadline automatiche perché il backend le ignorava. Finché non
esiste un limite provider verificabile o un diverso controllo di spesa
autorizzato, il runbook vieta la creazione del pod.
Il [record della deadline](../../benchmarks/results/c71-runpod-deadline-audit-2026-10-03-5fba934b009f.json)
conserva fonte, versione, controlli locali e decisione senza attribuire
credito hardware o protocollare.

I criteri per il [primo esperimento della prova](runpod-tests.md#esperimento-della-prova)
non richiedono una dimostrazione preventiva del tempo H100: i tempi
mancanti si misurano nel minimo esperimento autorizzato.
Si dà priorità all'integrazione; ulteriori ottimizzazioni isolate
sono giustificate da correttezza o impatti di almeno 16 MiB o 0,5 s.

## Contratto delle risorse

| Quantità | Requisito |
|---|---:|
| Tempo completo per risposta sulla singola H100 | ≤65 s |
| Certificato completo iniziale, setup di sessione incluso | ≤130.000.000 byte |
| Certificato completo di ogni continuazione | ≤40.000.000 byte |
| Memoria globale H100 | <80.000.000.000 byte, con almeno 1 GiB libero nel piano |
| Arena per tutti i temporanei dell'implementazione | 6.442.450.944 byte, con almeno 256 MiB liberi |
| W packed | 61.394.690.560 byte |

Il codec B12 corrente supera analiticamente 40 MB nelle continuazioni.
È ammesso concludere la valutazione della dimensione con questo esito
negativo; il limite inferiore non diventa una prova prodotta o un limite
superiore. Questa disposizione non allenta tempo, memoria o sicurezza.

Si conta tutto il lavoro: generazione, ricostruzione del testimone, PCG,
prova, serializzazione e trasferimenti necessari. Il lavoro totale su
ogni prefisso deve essere non crescente rispetto alla baseline a parità
di modello, semantica, token e sicurezza. Caricamento globale e setup di
sessione hanno voci distinte; non vi si nasconde lavoro della risposta.
Memoria aggiuntiva esterna può contenere solo materiale globale del modello,
riutilizzabile senza crescita con le sessioni. Nessuno spill dinamico.
Quattro letture W sono un obiettivo di ottimizzazione, non un limite rigido.

## Uso dei documenti

Questi cinque file costituiscono la documentazione operativa. `design.md`
definisce obiettivo e scelte; `specs.md` descrive algoritmi, dati e codice;
`security.md` contiene enunciato, dimostrazione e obblighi residui;
`local-tests.md` e `runpod-tests.md` definiscono verifiche e procedure.
Le [decisioni ed evidenze storiche](../c7.1-history/README.md) conservano
provenienza e fallimenti, senza fornire istruzioni operative concorrenti.
