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

Il runner esplicito `experiment-cuda` collega ora tutti i 13 producer,
inferenza token-causale, replay A, PCS/range/GKR, verifica e promozione
per O=0/150/300. È un prototipo **misto GPU/CPU**. L'istruzione del
4 ottobre antepone alla campagna H100 la riduzione locale dei temporanei:
owner CUDA a rilascio fisico, coset raggruppati, aperture contigue e S1
ridimensionato, con un contatore comune alle allocazioni dei due ruoli.
Il massimo ammesso dal contatore è 5.905.580.032 B; aggiungendo la riserva
esplicita di 256 MiB per runtime/allocator/stack si ottengono
6.174.015.488 B e 256 MiB di margine sul tetto. Questa riserva è ancora
un'ipotesi fisica da verificare, non una misura H100. Un limite che rifiuta
allocazioni non dimostra da solo il completamento del caso canonico.

[canonical_device.rs](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_device.rs)
possiede la sessione numerica: stessa Arc W del commitment, un runtime
con stream/arena, tabelle, una generazione di checkpoint/istogrammi e KV
append-only con capacità condivisa per 450 token. Il preparatore non
riceve transcript, correlazioni o monete PCS. I getter/scanner leggono
quegli originali o li rigenerano dalle stesse ricette/tabelle e token.
Le viste storiche conservano il limite causale. Il registro autorizza il
predecessore; la promozione numerica segue completamento verificato e
journal durevoli su entrambi i ruoli. Errori, panic o CUDA assente sono
terminali: nessun fallback di inferenza, retry o seconda arena.

Matrix usa quattro MMA INT8 con correzioni e raw i64; Norm usa soglie
quadrate u128 esatte; QK/PV sono attualmente dot product interi scalari,
non MMA. RNE, Affine/Gate, embedding, GELU/softcap, RoPE, EXP30 e argmax
usano originali e codec canonici. Il gather A produce finestre residenti
per il range sullo stesso owner. Restano **esplicitamente CPU** PCS
FFT/Merkle/query/resti e contrazioni, GKR non-range/MAC, Seed6 reale AES,
codec, verificatore e journal. Le righe/finestre originali richieste da
questi consumer sono scaricate in staging bounded; non si tratta di una
PCS GPU o di assenza assoluta di D2H. Il gather range W rimane CPU,
con upload signed per finestre fino a 256 MiB. La
[contabilità del percorso misto](specs.md#runner-cuda-sperimentale-e-conto-simultaneo)
distingue payload, capacità riservate, trasferimenti e picchi da misurare.

Il runner registra wall annidati, traffico applicativo nei due sensi,
census simultanei ai confini delle fasi, ledger cumulativo CUDA e RSS/HWM
dell'intero processo. Non sommare picchi o contatori cumulativi. Nel backend
nativo l'intervallo di inferenza include cattura KV/checkpoint/istogrammi;
il resto della risposta include replay/prova e attesa della verifica.
Monitor esterni restano necessari per CPU-time, campionamento HBM e kill.
Non sono acquisiti certificati canonici, forward su W reale o misure D34/D35.

Il [checkpoint pulito del runner](../../benchmarks/results/c71-device-runner-local-2026-10-04-1ec6720bb494.json)
registra build Rust/eseguibile e CUDA sm_90, 38 test Rust e 12 Python
passati; il test hardware esplicito è ignorato localmente. Include
anche una prova CPU ridotta con Seed6/AES e promozione dopo journal,
non tre certificati canonici GPU. Clippy termina con warning, non è lint-clean.

I checkpoint [RMS/attention](../../benchmarks/results/c71-attention-local-2026-10-04-85e77ea66b6f.json),
[range condiviso](../../benchmarks/results/c71-shared-range-local-2026-10-04-b6639a3fc3ad.json)
e [prefissi KV](../../benchmarks/results/c71-kv-prefix-local-2026-10-04-facc742ede52.json)
conservano componenti locali verificati, non credito GPU. Il
[precedente fallimento CPU](../../benchmarks/results/c71-nonlinear-local-2026-10-04-870ec1faf05d.json)
nell'asserzione di esaurimento dopo rifiuto resta un fallimento distinto.
Il [tentativo Seed6 ridotto](../../benchmarks/results/c71-real-two-attempts-2026-10-03-262e89febe2c.json)
ha completato una risposta ma superato 60 s nella seconda: non dimostra
due promozioni. Il readiness audit storico `NOT_READY` non viene riscritto
o interpretato come divieto dell'integrazione locale ora completata.

La calibrazione resta CPU. Export completo, piano pubblico e
[driver indipendente](../../benchmarks/results/c71-independent-driver-2026-10-02-645e855645d8.json)
sono implementati e testati sui 13 operatori/schedule, ma confronto sui
pesi reali, Γ numericamente validato e tempo completo sono ancora da
acquisire nella campagna autorizzata. La prova non certifica di per sé
provenienza W, qualità del modello o correttezza delle tabelle.

**Premesse residue.** I lemmi Lean giustificano le identità richiamate in
[security](security.md), non l'implementazione CUDA, la schedulazione,
il gather, l'immutabilità fisica o la composizione Seed6. Il replay nativo
assume determinismo dei kernel corretti su W/tabelle sigillati, token
fissati e prefissi KV originali; controlla token rigenerati e copertura,
ma non conserva un digest privato di tutta A per confrontare ogni replay.
La PCS/MAC continua a terminare negli originali. Test finiti, driver
simulato e compilazione sm_90 non scaricano queste premesse.

La campagna H100 del 4 ottobre è autorizzata sul pod `z3h2njpctmduix`
per il primo checkpoint diagnostico, con termine massimo di 6 ore e
spegnimento gestito dall'agente. Non è richiesto un preventivo economico.
Il bundle esterno in `artifact/c7.1-pod/` è limitato a 10 GB complessivi:
shard e packed vengono ricreati sul pod, mentre calibrazione completata,
ricette, tabelle e identità restano riutilizzabili con i controlli del
[runbook](runpod-tests.md#stato-e-sequenza-operativa). La nuova H100 richiede
comunque parità e misure fisiche; l'autorizzazione non concede credito
numerico o protocollo a fasi non completate.

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

Il precedente subtotal 10.737.418.240 B (slab CUDA più coset host) è
superato nel codice: non esiste più una prenotazione CUDA fissa di 6 GiB.
Il budget comune comprende PCS, GKR, Seed6, staging, prove, entrambi i
ruoli e tutte le capacità Rust trattenute, oltre ai buffer CUDA allineati.
Si esclude soltanto il payload W packed immutabile. Le allocazioni grandi
host usano una soglia glibc mmap fissa, evitando che i workspace liberati
rimangano nei successivi picchi come grandi cache dell'allocatore.
Il [conto corrente](specs.md#runner-cuda-sperimentale-e-conto-simultaneo)
separa limite imposto, subtotal derivati dalle shape, test ridotti e
riserva fisica. Il [checkpoint locale](../c7.1-history/temporary-memory-2026-10-04.md)
conserva decisioni, limiti e fallimenti. Nessuna riclassificazione dello scratch della risposta.

I gruppi di coset mantengono 512 scan iniziali A e 1.024 W, ma eseguono
quattro accumulazioni di campo per coefficiente iniziale (due per S1/S2),
con FFT più piccole. Il lavoro extra è della prova: non eredita i tempi
analitici precedenti e non dà credito al requisito di lavoro non crescente.
Restano invariati protocollo, transcript, monete e MAC; non è introdotto
un lemma Lean di raffinamento dell'allocatore o dei kernel. Le assunzioni
numeriche/formali già aperte restano quelle della sezione sicurezza.

## Uso dei documenti

Questi cinque file costituiscono la documentazione operativa. `design.md`
definisce obiettivo e scelte; `specs.md` descrive algoritmi, dati e codice;
`security.md` contiene enunciato, dimostrazione e obblighi residui;
`local-tests.md` e `runpod-tests.md` definiscono verifiche e procedure.
Le [decisioni ed evidenze storiche](../c7.1-history/README.md) conservano
provenienza e fallimenti, senza fornire istruzioni operative concorrenti.

Il [record locale a SHA pulita 82dae48](../../benchmarks/results/c71-temporary-memory-local-2026-10-04-82dae4818962.json) conserva 41 test Rust
e 11 Python passati, build lib/runner/sm_90, ledger, hash e fallimenti
intermedi. Un test GPU resta intenzionalmente ignorato. Non acquisisce
W reale, esecuzione canonica o conformità fisica H100.
