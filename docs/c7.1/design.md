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

Il runner esplicito `experiment-cuda` collega ora tutti i 13 producer,
inferenza token-causale, replay A, PCS/range/GKR, verifica e promozione
per O=0/150/300. È un prototipo **misto GPU/CPU**, con
owner CUDA a rilascio fisico, coset raggruppati, aperture contigue e S1
ridimensionato. Un contatore comune copre le allocazioni dei due ruoli.
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
per il range sullo stesso owner. Il commitment iniziale W usa accumuli,
FFT e hash/Merkle residenti. Restano **esplicitamente CPU** monete/sali PCS,
PCS A e extension, query/resti e contrazioni, GKR non-range/MAC, Seed6 reale AES,
codec, verificatore e journal. Le righe/finestre originali richieste da
questi consumer sono scaricate in staging bounded; non si tratta di una
PCS interamente GPU o di assenza assoluta di D2H. Il gather range W rimane CPU,
con upload signed per finestre fino a 256 MiB. La
[contabilità del percorso misto](specs.md#runner-cuda-sperimentale-e-conto-simultaneo)
distingue payload, capacità riservate, trasferimenti e picchi da misurare.

Il runner registra wall annidati, traffico applicativo nei due sensi,
census simultanei ai confini delle fasi, ledger cumulativo CUDA e RSS/HWM
dell'intero processo. Non sommare picchi o contatori cumulativi. Nel backend
nativo l'intervallo di inferenza include cattura KV/checkpoint/istogrammi;
il resto della risposta include replay/prova e attesa della verifica.
Monitor esterni restano necessari per CPU-time, campionamento HBM e kill.
Non sono acquisiti certificati canonici o misure D34/D35 della prova.

Il codice del runner è compilato e verificato su componenti ridotti;
la [parità H100](../../benchmarks/results/c71-h100-corrected-parity-2026-10-04-d3c2fa95eaf7.json)
conferma operatori sintetici e MAC originali, senza certificati canonici.
I fallimenti e le revisioni precedenti restano nei
[record originali](../../benchmarks/results/) e nell'[archivio](../c7.1-history/README.md).

## Risultati attuali e prossime ottimizzazioni

Γ è **ammesso** per modello, byte W, workload, semantica, scale, tabelle
e ricette pinned: il [record di ammissione](../../benchmarks/results/c71-gamma-admission-2026-10-07-868a3e8.json)
chiude i cinque controlli. Due replay interi hanno `responses` identiche:
450 token, 3.471 sorgenti A per contesto, 120 sorgenti KV finali con
450 righe. Il confronto indipendente completo dura 1.819,70 s; replay
con traccia e confronto richiedono 3.324,18 s esterni. Il pilot FP64
completo dura 853,58 s, 928,84 s esterni. La parità floating misurata sul
prefisso rispetta il bound dichiarato e conserva scale/token, ma non è
bitwise né un confronto floating dell'intero workload. L'ammissione si
fonda sui replay interi e sul confronto indipendente esatto.

La [diagnostica della prova](../../benchmarks/results/c71-cuda-experiment-2026-10-07-868a3e8.json)
resta **INCOMPLETA**: exit 124, wall 2.461,09 s, prima delle risposte,
senza journal o certificati. Il commitment iniziale W è CPU: 1.024
scansioni, circa 62,87 TB di letture logiche, oltre a sali, FFT e Merkle.
È condiviso fra le tre risposte dello stesso processo; la CLI lo
ricostruisce a ogni avvio e non riprende installazioni parziali.

La campagna del 7 ottobre è chiusa, con arresto del pod verificato.
Massimi campionati: 126.148.050.944 B RSS+HBM e 290.287.030.272 B
cgroup+HBM, quest'ultimo inclusivo di cache dei file e altri processi.
Picco host del cgroup 228.069.777.408 B su 250.999.996.416 B; HBM
62.605.230.080 B su 80 GB. Nessun OOM o swap; picco simultaneo completo
e margine dell'arena della prova restano aperti. Il
[runbook](runpod-tests.md#riuso-del-bundle) identifica i bundle da riusare.
Le cronache, i tentativi falliti e le stime superate sono nel
[design archiviato](../c7.1-history/design-2026-10-07.md) e nel
[runbook archiviato](../c7.1-history/runpod-tests-2026-10-07.md).

Il percorso principale riusa Γ dopo verifica delle identità e dell'impatto
di eventuali modifiche; la calibrazione si ripete quando l'ammissione
pertinente è invalidata. Le priorità sono telemetria durevole di sali,
scansioni, FFT e Merkle, poi ottimizzazione del percorso PCS e delle
ricostruzioni A sulla H100, con parità esatta e conto completo dei costi.
Il [checkpoint locale telemetria/XOF](../../benchmarks/results/c71-crypto-preparation-local-2026-10-08-04ab8ed1c4ce.json)
integra il buffering da 4 KiB: 5,95× sul sampler Goldilocks ARM, parità
di stream/seek/snapshot/cap e catene WHIR ridotte con transcript/MAC
originali. La fixture PCS aggiunge 1,57 ms per 60 record durevoli.
Il positivo Seed6/AES ridotto termina in 50,29 s, con picco congiunto
contato 116.430.690 B e nessun rifiuto. Sono componenti locali, non
prestazioni H100, prova canonica o picco fisico completo. La
[decisione e i prossimi passi](../c7.1-history/crypto-preparation-2026-10-08.md)
distinguono questo primo checkpoint dall'intero goal ancora attivo.

Il goal dell'8 ottobre prepara **l'intero percorso crittografico H100**
in locale: telemetria/XOF, commitment W residente, blocchi di colonne e
accumuli esatti, producer A collegati alla PCS, quindi aperture/GKR/range/
attention/sincronizzazioni secondo il profilo. Baseline `9033c64`;
`47135ca` aggiunge sole istruzioni documentali. Il goal si conclude quando
codice, parità ridotte, screen e procedure sono pronti, prima della nuova
campagna. Hardware e durata richiedono nuova autorizzazione.

La prima integrazione usa buffering sequenziale XOF da 4 KiB e
[telemetria durevole](specs.md#telemetria-durevole-del-percorso-crittografico).
Replay per foglia senza buffer; snapshot/seek al cursore logico. Geometrie,
scansioni W/A e parametri crittografici rimangono quelli correnti in questa
modifica. Γ mantiene le identità ammesse: producer, scale, tabelle, ricette,
W e workload non sono toccati da telemetria e buffering.

Il [passo W hash](../c7.1-history/crypto-w-hash-2026-10-08.md) aggiunge
compressione BLAKE3 condivisa e operazioni GPU di foglia incrementale e
Merkle nello stesso owner. CV da 32 B/foglia, mezzo blocco pendente nel
ring, sali a finestre e pubblicazione dopo controllo terminale. Il
collegamento al Tree è ora selezionato per W in `experiment-cuda`. Il merge strided a gruppi
ricompone l'ordine naturale con un frontier di sette livelli per 128
gruppi di 32 coset, da verificare anche con gli accumuli residenti. La
schedule A rimane separata; nessuna ricostruzione aggiuntiva è introdotta.
Il subtotal 2 GiB valori + 1 GiB CV non comprende FFT, potenze, sali,
frontier/cache, owner residente, host e riserva fisica.
Il [record locale pulito hash W](../../benchmarks/results/c71-crypto-w-hash-local-2026-10-08-0bf5814bf9c4.json)
ha cinque test Rust e undici controlli Python positivi, UBSan e 27
rifiuti terminali verificati. Picco congiunto della fixture 9.361.975 B,
RSS massimo dei test/compilatori discendenti 193.908.736 B. Non è un
tempo o picco H100; quel record precede l'integrazione nel Tree.

Il [componente accumuli/FFT W](../c7.1-history/crypto-w-scan-fft-2026-10-08.md)
collega nelle fixture W sigillato, accumuli interi esatti, FFT esistente
in-place e hash/Merkle incrementali. Parità campo per campo e di tutti
i digest su tre geometrie con 32 coset/128 colonne, inclusi 256
contributi e 1.536 pad; 24 rifiuti terminali e modulo i128 indipendente
su 526.336 prefissi. Il conto candidato comprende potenze basse da
256 MiB, twiddle da 8 MiB e pad originali, senza duplicare il ring.
Il [passo Tree W](../c7.1-history/crypto-w-tree-2026-10-08.md) integra
la schedule nel runner CUDA: stessi getter/monete/pad, root e aperture
ridotte esatte, con contatori host/device congiunti. Il confronto completo
di transcript/MAC usa una tabella di righe iniziali di riferimento da
16 MiB soltanto nella fixture; il test distinto di aperture esercita il
getter di produzione. Il D15 non cached supera ancora 60 s locali ed è
conservato come obbligo prestazionale, senza credito di completamento.
128 scansioni W sono ora la schedule selezionata CUDA, ancora analitica
per il workload pinned; A conserva 512 ricostruzioni. Tensor Core, A→PCS
e accelerazione delle aperture restano aperti. Nessun credito
CUDA/H100 o nuova autorizzazione hardware. La somma signed <2^87 e
la sua riduzione sono identità controllate localmente, senza lemma Lean
di raffinamento dell'implementazione o dello scheduling CUDA.
Il [record pulito accumuli/FFT W](../../benchmarks/results/c71-crypto-w-scan-fft-local-2026-10-08-e66e0fbd45db.json)
conserva sette selezioni Rust e venti controlli Python positivi, parità
di tutti i valori/foglie/livelli dei gruppi e 24 arresti. Picco payload
congiunto ridotto 5.983.714 B; RSS massimo test/descendenti 235.655.168 B,
compiler O0 2.465.947.648 B separato. Preserva anche build/fixture fallite
e correzioni; nessun risultato completo W o H100 è acquisito.

Le geometrie fisiche attuali (W CUDA 32 coset/otto colonne e 128 scansioni;
riferimento CPU W quattro coset/1.024; A quattro coset/512)
sono scelte implementative modificabili. Alternative richiedono
equivalenza verificata, ordine di sali/pad/root e MAC originali preservato,
NoPeek e nuovo conto completo di lavoro, memoria e capacità simultanee.
I parametri crittografici e i vincoli di sicurezza/risorse restano invariati.
I fallimenti delle geometrie escluse restano validi per le loro premesse;
riaprirle richiede risolvere e verificare la causa dell'esclusione.
La [decisione dell'8 ottobre](../c7.1-history/operating-rules-2026-10-08.md)
registra il motivo e l'autorizzazione a queste ottimizzazioni.

**Premesse residue.** I lemmi Lean giustificano le identità richiamate in
[security](security.md), non l'implementazione CUDA, la schedulazione,
il gather, l'immutabilità fisica o la composizione Seed6. Il replay nativo
assume determinismo dei kernel corretti su W/tabelle sigillati, token
fissati e prefissi KV originali; controlla token rigenerati e copertura,
ma non conserva un digest privato di tutta A per confrontare ogni replay.
La PCS/MAC continua a terminare negli originali. Test finiti, driver
simulato e compilazione sm_90 non scaricano queste premesse.

Le regole permanenti per durata specifica della campagna, limiti AS,
trial successivi, pubblicazione e conservazione sono definite una sola
volta nel [runbook](runpod-tests.md#autorizzazione-e-limiti).

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
