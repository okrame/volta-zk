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
finestre e PCS senza vettori sorgente completi. La configurazione attuale delle
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

Il runner esplicito `experiment-cuda` collega i 13 producer, inferenza
causale, replay A, PCS/range/GKR, verifica e promozione per O=0/150/300.
È un percorso misto GPU/CPU. Il seguente stato riguarda l'ultimo
checkpoint locale validato; integrazione software e parità ridotta
non attribuiscono prestazioni o picco fisico H100.

| Parte | Stato e confine |
|---|---|
| Telemetria e XOF | Integrati: fasi e avanzamento durevoli, lavoro/trasferimenti/census, buffering sequenziale da 4 KiB con stream/seek/replay originali |
| Commitment iniziale W | Integrato nel Tree/runner: accumuli esatti, FFT, foglie incrementali e Merkle sul common owner; 32 coset/otto colonne, 128 scansioni analitiche sul pinned |
| Commitment iniziale A | Producer residenti collegati alla PCS, quattro coset/tutte le 128 colonne, istogramma fuso nel primo replay; 512 ricostruzioni conservate, nessun download per riga nel commitment |
| Sali iniziali W/A | Prescan e replay selezionati sullo stream comune, cursore logico e cap originali; niente bande host/upload sali |
| FFT naturale diretta/inversa | Primitiva integrata nell'owner con parità indipendente; caller query A, fattori/resti e S1 ancora CPU nel checkpoint validato |
| Closure lineare | Una scan originale per round CPU, D·live visite; versione GPU ancora da collegare |
| Accumulo W Tensor Core | Candidata limb16 esatta e confronto esplicito sul medesimo owner; ordinario rimane predefinito |
| QK/PV | Default scalare esatto; candidata MMA con prefisso causale comune e bordo scalare non selezionata |
| Resto della prova | Extension PCS, query/resti/contrazioni, GKR non-range/MAC, Seed6 reale AES, codec, verifica e journal dichiarati CPU |

[canonical_device.rs](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_device.rs)
possiede la sessione numerica: stessa Arc W del commitment, un solo
runtime/stream/arena, tabelle, una generazione di checkpoint/istogrammi
ed una capacità KV per 450 token. Matrix usa quattro MMA INT8 esatte,
Norm soglie u128 e gli altri producer la semantica canonica. Producer e
preparatore non ricevono transcript, monete PCS o correlazioni; le viste
storiche mantengono il prefisso causale. Errori, panic, CUDA assente e
cleanup falliti sono terminali, senza retry o fallback.

I consumer CPU usano staging privato bounded. Il range A è residente;
il gather range W usa ancora upload signed per finestre fino a 256 MiB.
La PCS completa non è ancora residente. Il
[conto tecnico](specs.md#runner-cuda-sperimentale-e-conto-simultaneo)
distingue capacità, trasferimenti e stati simultanei: tetto payload
5.905.580.032 B, più riserva fisica esplicita di 256 MiB, totale
condizionato 6.174.015.488 B e ulteriori 256 MiB di margine. La sufficienza
della riserva e il completamento canonico sono aperti.

La telemetria misura wall annidati, traffico applicativo, census ai
confini delle fasi, ledger cumulativo CUDA e RSS/HWM. Non sommare picchi
separati o contatori cumulativi. Monitor esterni devono ancora misurare
CPU-time, HBM e arresti. Non sono acquisiti certificati canonici o misure
D34/D35 complete della prova. La
[parità H100 precedente](../../benchmarks/results/c71-h100-corrected-parity-2026-10-04-d3c2fa95eaf7.json)
riguarda operatori sintetici e MAC originali, non il percorso ottimizzato.

## Risultati attuali e prossime ottimizzazioni

Γ è **ammesso** per modello, byte W, workload, semantica, scale, tabelle
e ricette pinned. Si riusa dopo verifica di identità e impatto delle
modifiche; si ripete la calibrazione solo quando l'ammissione pertinente
è invalidata. La diagnostica canonica rimane **incompleta**: timeout nel
commitment W CPU dopo circa 41 minuti, prima delle risposte. La schedule
misurata tentava 1.024 scansioni W, circa 62,87 TB logici, oltre a sali,
FFT e Merkle. La CLI ricostruisce il commitment a ogni avvio e non
riprende un'installazione interrotta. La campagna precedente è chiusa.

Il goal locale prepara **l'intero percorso crittografico per H100 80 GB**,
baseline `9033c64`. Si conclude quando codice, parità ridotte, benchmark
rappresentativi, conto completo e procedure sono pronti, prima della
campagna hardware. Il goal è ancora attivo; nuova H100 e durata
richiedono nuova autorizzazione.

Le prossime integrazioni riguardano query A iniziali residenti e S1,
poi aperture/closure/GKR/range e sincronizzazioni secondo il profilo.
Le query usano già finestre bounded; il loro caller deve conservare
batch, richieste e ricostruzioni. S1 conserva 35 passaggi non-query fino
alla retention: evitare una seconda matrice device da 1 GiB o una doppia
retention da 3,22 GB. Le primitive FFT naturali sono pronte, il caller
non è ancora validato come residente. Valutare TMA, fusioni e CUDA Graphs
su costi misurati. Il confronto W ordinario/Tensor e la selezione QK/PV
richiedono compilazione, parità e misura GPU nella futura campagna.

Le geometrie fisiche W CUDA 32 coset/otto colonne, CPU W quattro coset
ed A quattro coset sono modificabili con equivalenza esatta e nuovo
conto di scansioni/ricostruzioni, memoria e capacità simultanee. Non
trasferire implicitamente il blocco di colonne W ad A. Sali/pad/root,
ordine naturale, transcript, NoPeek e MAC originali devono rimanere
invariati. Le geometrie escluse restano escluse per le loro premesse;
riaprirle richiede risolvere e verificare la causa.

Gli obblighi prestazionali già quantificati restano visibili: A iniziale
512 ricostruzioni; sali prescan/replay almeno 274.877.906.944 B XOF W e
137.438.953.472 B A per risposta, anche dopo eliminazione degli upload
sali; D15 W/A non cached e un test CPU lookup/GKR/WHIR superano 60 s
locali. Cache di riferimento da 16 MiB solo nelle fixture composte
non risolvono tali timeout in produzione. Gli screen W/A nominati sono
4.618.167.208 / 5.585.161.864 B prima degli altri owner host: il secondo
lascia 320.418.168 B al payload, senza ammissione del picco completo.

**Premesse residue.** I lemmi Lean richiamati in [security](security.md)
non raffinano implementazione CUDA, scheduling, gather, immutabilità
fisica o composizione Seed6. Il replay assume determinismo dei kernel
corretti su W/tabelle sigillati, token fissati e prefissi KV originali;
controlla token rigenerati e copertura, senza un digest privato di tutta
A confrontato a ogni replay. PCS usa v³=v+1, MAC u³=2; gli endpoint
rimangono VOLE-autenticati sugli originali. Test finiti, driver simulato
e compilazione sm_90 non scaricano queste premesse.

### Evidenze e decisioni

Questa è la mappa dei checkpoint; dettagli di fixture, RSS, tempi,
fallimenti e provenienza rimangono nei record e nelle storie datate.
Ogni nuova integrazione deve avere parità esatta ridotta, benchmark
rappresentativo e conto completo prima della selezione. Le evidenze
locali sono `credit:false`, senza compilazione o esecuzione CUDA.

| Evidenza | Ambito e limite |
|---|---|
| [Ammissione Γ](../../benchmarks/results/c71-gamma-admission-2026-10-07-868a3e8.json) | Due replay interi e confronto indipendente completo sul workload pinned; non certificati canonici |
| [Diagnostica canonica](../../benchmarks/results/c71-cuda-experiment-2026-10-07-868a3e8.json) | Timeout iniziale W, prima delle risposte; [cronaca](../c7.1-history/design-2026-10-07.md) e [runbook datato](../c7.1-history/runpod-tests-2026-10-07.md) conservano risorse campionate e chiusura |
| [Telemetria/XOF](../c7.1-history/crypto-preparation-2026-10-08.md) | Stream/seek/cap, JSONL durevole e positivo Seed6/AES ridotto |
| [Hash W](../c7.1-history/crypto-w-hash-2026-10-08.md), [accumuli/FFT W](../c7.1-history/crypto-w-scan-fft-2026-10-08.md), [Tree W](../c7.1-history/crypto-w-tree-2026-10-08.md) | Incremental hash, valori/campi, root/aperture, transcript/MAC; timeout uncached conservato |
| [Consumer A](../c7.1-history/crypto-a-source-2026-10-08.md), [Tree A](../c7.1-history/crypto-a-tree-2026-10-08.md) | Codec originale, producer→PCS, istogramma, root/aperture e prova composta; timeout uncached conservato |
| [Closure/XOF/confronto Tensor](../c7.1-history/crypto-components-2026-10-09.md) | Componenti esatti e confronto owner; [correzione causale QK/PV](../../benchmarks/results/c71-attention-causal-local-2026-10-09-29a257b4476b.json) distinta dal finding iniziale |
| [Sali owner/Tree](../c7.1-history/crypto-salts-owner-2026-10-09.md) | Stream privato, root/aperture/transcript/MAC e conto aggiornato; gerarchia CUDA non eseguita, timeout CPU conservato |
| [FFT naturale owner](../c7.1-history/crypto-transform-2026-10-09.md) | Diretta/inversa esatte, geometria dispari e guard; primitiva integrata, query caller ancora CPU al source validato |
| [Regole operative](../c7.1-history/operating-rules-2026-10-08.md), [temporanei](../c7.1-history/temporary-memory-2026-10-04.md) | Ragioni delle decisioni; autorizzazioni correnti definite nel [runbook](runpod-tests.md#autorizzazione-e-limiti) |

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
Il ripiego analitico autorizzato è 47,84 / 54,87 / 61,80 MB per
O=0/150/300: sono i limiti inferiori del corpo in
[specs](specs.md#ordine-e-formato-del-certificato), non dimensioni misurate,
limiti superiori o nuovi cap dei certificati. È ammesso concludere così
la valutazione negativa del requisito 40 MB; questa disposizione non
allenta tempo, memoria o sicurezza.

Si conta tutto il lavoro: generazione, ricostruzione del testimone, PCG,
prova, serializzazione e trasferimenti necessari. Il lavoro totale su
ogni prefisso deve essere non crescente rispetto alla baseline a parità
di modello, semantica, token e sicurezza. Caricamento globale e setup di
sessione hanno voci distinte; non vi si nasconde lavoro della risposta.
Memoria aggiuntiva esterna può contenere solo materiale globale del modello,
riutilizzabile senza crescita con le sessioni. Nessuno spill dinamico.
Quattro letture W sono un obiettivo di ottimizzazione, non un limite rigido.

Il budget comune comprende PCS, GKR, Seed6, staging, prove, entrambi i
ruoli e tutte le capacità Rust trattenute, oltre ai buffer CUDA allineati.
Si esclude soltanto il payload W packed immutabile. Le allocazioni grandi
host usano una soglia glibc mmap fissa, evitando che i workspace liberati
rimangano nei successivi picchi come grandi cache dell'allocatore.
Il [conto corrente](specs.md#runner-cuda-sperimentale-e-conto-simultaneo)
separa limite imposto, subtotal derivati dalle shape, test ridotti e
riserva fisica. Il [checkpoint locale](../c7.1-history/temporary-memory-2026-10-04.md)
conserva decisioni, limiti e fallimenti. Nessuna riclassificazione dello scratch della risposta.

I gruppi CPU mantengono 512 scan iniziali A e 1.024 W, ma eseguono
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
