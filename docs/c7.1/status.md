# C7.1 — Goals and current status

Aggiornato al 2026-09-27. [Design](design.md) · [Security](security.md) ·
[Evidence](evidence.md) · [Decisions](decisions.md) · [Indice](../README.md).
Questa pagina contiene stato, autorizzazione e prossimo lavoro; requisiti,
prove e risultati dei test hanno ciascuno la propria sede nei link sopra.

## Current result

**Goal locale in corso: C7.1 pronto per il minimo esperimento H100.**
Il proprietario ha confermato il 2026-09-26 che non occorre dimostrare
i 65 s prima delle misure. La chiusura richiede costruzione integrata
corretta su input ridotti, ledger completo senza costi omessi, picco
pianificato con almeno 256 MiB liberi e lower congiunto compatibile
con 65 s a O=0/150/300; poi harness/input, SHA pulita, comando,
durata massima, costo e soglie verificabili per il minimo esperimento.
Solo allora il goal locale è achieved e si presenta la proposta H100.
Il lavoro locale è autorizzato e non è stalled; GPU e spesa restano
subordinate a successiva autorizzazione. Il tracker automatico corrente
conserva questo goal come attivo; i gate sottostanti restano il criterio
di chiusura.
Priorità all'integrazione; nessun nuovo census o ottimizzazione isolata
salvo correttezza o impatto ≥16 MiB di picco / ≥0,5 s di tempo.

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
ancora da chiedere. Il proprietario ha selezionato **Γ calibrato del modello
reale** per il preflight; il profilo sintetico non lo sostituisce.
Il proprietario ha confermato che Γ è **da calibrare**: non si attende un
percorso a un artefatto già esistente. È selezionato il **workload C7.1
fissato nei tre contesti O=0/150/300, senza certificazione di qualità generale**.
Il [percorso preparatorio](preflight.md#real-calibrated-gamma) distingue
quantizzazione W e inizializzatore A disponibili, validazione da eseguire ed esecuzioni
pesanti ancora non autorizzate.
È implementato il dispatcher numerico per righe del DAG canonico, con
ricette RMS/RNE originali, indirizzi QK/KV/RoPE e driver causale per token;
il relativo storage CPU ora raccoglie range e istogrammi, conserva KV i16
causale e libera le righe all'ultimo consumer. Il lettore packed usa una
sola riga W. L'ingest ora seleziona automaticamente gli esponenti W con
il componente nativo, conservando hash dei due shard e pubblicazione
atomica del packed; è controllato su shard piccoli. Sono controllati
sottografi con input sintetici; restano pesi
reali, scelta delle scale e validazione completa. L'harness offline ora
lega una mappa candidata ai tre contesti, genera le tabelle con il
riferimento certificato e trasferisce solo KV di trial terminati. Sono
controllati input pubblici e passaggio dello stato, non un forward completo.
L'inizializzatore floating riusa il DAG nativo e W packed, propone una
sola mappa A dai tre contesti e conserva provenienza/errori. I controlli
coprono un grafo piccolo e gli ID canonici, non attivazioni reali.
Restano esecuzione sui pesi reali, eventuale adattamento delle scale e
replay intero positivo; non è ancora Γ calibrato né modello completo.
Il raccordo al ledger ora usa le ricette RMS della candidata e ricompila
le riserve dei tre contesti; il controllo nonzero resta sintetico.

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

Il nuovo percorso integrato **O=0** sostituisce Snapshot/A densi con un
reader ordinato: ricava il token dai logits causali, valida tutti i producer
prima del commitment e conserva soltanto cut/KV ridotti, una riga numerica
e una finestra byte da 128 B. Lookup streaming e GKR sourcewise riusano lo
stesso corpo; range A, riduzione lineare e WHIR chiudono sugli stessi MAC.
Il verifier originale accetta una proof da **circa 7,75 MB**, consumando
**88.049 righe MAC** e ricostruendo la stessa ricevuta. Range e linear
sourcewise coincidono byte per byte con le rispettive prove dense a
monete fissate nel test. È correttezza ridotta con MAC ideali, non port
canonico, storia A streaming o PCG reale positivo.

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
il dispatcher per gli altri produttori è ora disponibile, ma resta il
collegamento completo al Prepare/prover canonico.
Il [provider compatto P0](evidence.md#original-p0-compact-provider) ora deriva inner, padding e route dai descrittori,
con reshape testa/token e selezione delle righe del tied head; il runner
ridotto riusa questo corpo invece dei loop fissati a hidden=2. È controllato
su sorgenti originali piccole, non l'esecuzione P0 sui pesi canonici.
Non è ancora un'inferenza canonica.

L'[installazione W ridotta](evidence.md#replay-installed-w-with-ordered-a) ora passa la proof O=0 con Seed6 reale e A ordinata: un solo packed
immutabile alimenta Prepare e il getter PCS, senza la seconda copia W
virtuale densa. Range simmetrico e chiusura W passano dall'adapter comune
già usato per A. Il controllo usa t=4/h=19/ell=2; non è ancora
installazione canonica, tre accettazioni reali o picco fisico.

Le [righe PCS replay](evidence.md#native-fft-remainder-in-replay-openings) usano ora il riduttore FFT per blocchi con i pad
originali, invece di valutare tutta la sorgente per ogni query. È un
callback limitato a 1.024 richieste, non l'apertura canonica completa:
setup/valutazione quadratici e replay separati dei sottoalberi restano
espliciti. Passano parità WHIR, streaming ideale e O=0 W replay/A ordinata
con Seed6 reale, senza trasferire il ledger hardware.

Il [dispatcher RMS](evidence.md#borrowed-rms-correlation-intervals) passa ora gli intervalli MAC in prestito in entrambi
i ruoli, senza duplicare l'intera riserva prima delle statistiche. Il burn
completo resta nel pool; passano anche accettazione e rifiuto terminale
ridotti con Seed6. [GKR e byte endpoint](evidence.md#borrowed-gkr-and-byte-intervals) ora riusano la stessa forma in
prestito, con parità wire/FS/MAC e regressioni Seed6 passate; il census
separa heap posseduto e payload riservato. Non è
l'eliminazione di tutti i buffer interni né un nuovo margine fisico.
Il medesimo raccordo è ora [verificato per dispatcher e riduzione RNE](evidence.md#borrowed-rne-intervals),
senza cambiare probe, ricette o richieste sulle A originali; passano
anche accettazione e rifiuto terminale ridotti con Seed6.
Il [raccordo](evidence.md#borrowed-native-consumer-intervals) è esteso agli altri consumer numerici, EXP30/lookup e range/PCS:
non raccolgono più un pool bulk interno. Restano le altre allocazioni di
prova/sorgente e la verifica del picco completo, senza nuovo credito arena.

Il [corpo del verifier canonico](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_verify.rs)
ora implementa la schedule completa di security §3 con ricette comuni,
MAC originali e PCS W/vecchie A/A corrente. I controlli locali coprono
riserva, contesto e prefisso pubblico fino al rifiuto di un P0 incompleto;
non un certificato canonico positivo. Il [wrapper interno](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_state.rs)
collega ora registro posseduto dal verifier, header locale e pool reale:
burn prima del decoding, promozione solo dopo verifica completa e journal.
Il profilo lega i corpi delle tabelle, senza certificarne i valori numerici.
Il controllo reale a tre righe copre il rifiuto per capacità insufficiente
senza promozione o riuso. Il wrapper canonico riusa ora lo stesso adapter
di chiavi lazy Seed6 del ridotto e il corpo accetta iteratori a cardinalità
esatta. Lo [shortage Seed6](evidence.md#canonical-verifier-with-seed6-capacity)
usa solo setup 25+6; non è accettazione canonica.

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
promuovere KV. Separatamente, il nuovo wrapper opt-in Seed6 completa
**[un tentativo O=0 ridotto con AES reale](evidence.md#seed6-complete-reduced-native-proof)**,
88.049 MAC Fp3 e promozione
della stessa ricevuta nei due ruoli, con Snapshot/A densi piccoli ed ell=11.
Ora passa anche [O=0 con reader ordinato e Seed6 reale](evidence.md#ordered-source-with-real-seed6) a **ell=2**, senza
Snapshot/A densi. È una geometria ridotta di correttezza, non il profilo
canonico ell=11 o il run AES a tre tentativi.

## Next goal

**Ricerca Wasp completata su richiesta del proprietario (2026-09-25).**
Il [paper convertito con AnyDoc](../../sota/2026-1988-wasp.md) e lo
[screen di applicabilità](construction-screen.md#wasp-pcs-vole-ahe-e-limiti-del-port)
individuano una possibile riduzione dei byte PCS e un'identità di apertura
negli originali MAC. Il port letterale non soddisfa il contratto: endpoint
pubblico, nuove premesse AHE/PLTM, setup malevolo, riduzione MLE/same-W e
risorse restano da risolvere. Sono documentati un controesempio all'adapter
privato senza validazione SRS e un limite ZK della specifica SIMD scritta.
È ricerca `credit:false`, senza selezione di protocollo o nuove ipotesi.

**Due alternative EXP30, su richiesta del proprietario:** il NO-GO sotto
non chiude la ricerca. Lo [screen circoscritto](preflight.md#due-alternative-strutturali-exp30)
trova una prova dedicata del rapporto che richiederebbe un nuovo transcript,
e un'aggregazione privata dei pattern Boolean per i primi quattro round
che ricostruisce gli stessi cubici. La
[fattorizzazione dei pesi](preflight.md#pesi-di-gate-applicati-dopo-listogramma)
è ora implementata: blocchi da 16, sotto-pattern da 5 bit, gate mantenuti
separati fino alla riduzione. A O=300 i prodotti per i pesi scendono da
642.858.403.200 a **428.928.192**, senza replay per gate; i 3.922.447.766.400
aggiornamenti dei bin usano somme intere con riporto, senza riduzione modulare
nel loop; la riduzione avviene una volta per bin. Il producer usa fino a 64 lane Boolean
e i buffer raw sono liberati prima dei cubici. La parità nativa verifica
quattro round e continuazione MAC/FS; passa anche la proof integrata O=0.
Il lower della sola coda scalare resta 4,220242 s. Il payload aggiuntivo
è 661.947.264 B, collocato dopo il rilascio delle cache lookup nel piano
con margine. Una cache dei soli originali E/Pi/Z costa
132.192.000 / 391.392.000 / 650.592.000 B e sostituisce le ricostruzioni
del getter durante il rapporto; viene liberata dopo l’endpoint byte.
Non è il picco fisico completo. Il [record nativo aggiornato](evidence.md#native-exp30-wide-accumulators-and-original-cache)
conferma sei test Rust, otto Python e tre controlli arena su SHA pulita.
Nessun nuovo GO H100.
Il replay packed elimina ora le copie di livello e condivide gli antenati
in un DAG pubblico: a O=300 passa da 9.098.344.541.952 a
4.877.714.055.680 operazioni Boolean su word, più le gather originali.
Il [record su SHA pulita](evidence.md#native-exp30-replay-dag) conferma
parità a tutti i livelli e cinque test nativi, inclusa la proof integrata.
È riduzione del lavoro sorgente, senza credito di tempo GPU.
Il [consumer BMMA candidato](preflight.md#exp30-momenti-binari-bmma) elimina
nel modello gli aggiornamenti sparsi dei bin, compresi i Copy. Il percorso
con producer condiviso ha payload nominato di 489.850.540 B. Dieci kernel
compilano per sm_90 senza spill;
passano i [controlli CPU su SHA pulita](evidence.md#exp30-bmma-component)
di ricostruzione esatta, cubici e arena. È una
rappresentazione degli stessi aggregati privati, non un terzo protocollo.
[Packing e riduzione](evidence.md#exp30-moment-pipeline) hanno ora
controlli CPU e compilazione statica su SHA pulita. Il riferimento nativo a
momenti di un bit conserva proof/FS/MAC originali; non esegue CUDA. La
trasposizione usa 512 B shared per tile e nessun secondo stage globale.
Il [producer parallelo](evidence.md#exp30-shared-producer) legge direttamente E/Pi/Z originali: il piano
con riuso dopo barriera coincide con tutti i 95 livelli nativi e usa al
massimo 39.792 B shared per CTA. Eq sugli indici originali e pesi Fp3
hanno kernel e controlli CPU. Il raccordo dei 240 momenti al prefisso
nativo conserva proof/FS/MAC nel caso ridotto, anche con quadratici
non nulli. Restano lancio/controllo GPU e costruzione completa. Nessun positivo GPU o upper totale è ancora disponibile.
**Nuovo NO-GO del port scalare della fraction tree sui byte originali:**
lo [screen del percorso compilato](preflight.md#original-byte-tree-coefficient-screen),
[verificato su SHA pulita](evidence.md#native-moment-seam-and-byte-tree-screen),
esclude anche la variante Fp3 a sei prodotti base. Coefficienti byte più
range/commit/prime aperture, senza altri lavori, danno lower condizionali
**49,737497 / 70,116188 / 73,715684 s**. È NO-GO per O=150/300 della
schedule letterale, non della relazione o di ogni fattorizzazione possibile.
La LUT risparmia memoria ma non elimina l’enumerazione dei nodi.
La [contrazione pubblica dei nodi](preflight.md#original-byte-node-contraction)
riduce a **64** il numero complessivo di funzioni intermedie per cella,
contro 1.020: conserva i cubici e recupera i figli originali con un nuovo
passaggio sui byte autenticati. Passano l'oracolo algebrico ridotto, il
confronto Fp3 con tutti i 256 byte della LUT nativa e il piano nominato
con due buffer disgiunti. Il massimo indirizzo EXP30 resta
2.082.995.968 / 3.370.001.152 / 4.964.490.752 B; il massimo delle catene
note resta range A, con almeno 276.291.840 B non indirizzati. Non è il
picco fisico completo. Il margine stretto della fase range A non blocca
gli sviluppi reversibili nella catena EXP30, che ha spazio distinto;
i 256 MiB restano il criterio finale del piano integrato.
Il raccordo ridotto alla proof è ora passato: cubici e figli recuperati
entrano nella stessa autenticazione/FS, la proof coincide byte per byte
con la densa, claim errati e byte alterati sono respinti. Passa anche il
positivo lookup/GKR/WHIR O=0, con 88.049 MAC originali e senza Snapshot/A
densi; il trace registra 76 round contratti e otto terminali.
L'evaluatore CPU ora rigenera a batch con LUT pubbliche prepesate,
compatta il solo supporto pubblico e conserva un checkpoint. I fold
usano sorgente/destinazione disgiunte; feature e stati sono liberati
prima del recupero dei figli. Baseline zero ed Eq sulle coordinate
originali sono preservate nella proof integrata. Domini ragged sono
respinti senza letture o consumo MAC/FS. Il riferimento resta limitato
a domini completi ≤128 celle. Il caller canonico passa ora 288.000
intervalli causali, proiettati senza lista densa: tutti i round coincidono
col ledger a O=0/150/300. Gli stati mantengono le 12 lane private previste;
le quattro lane pubbliche zero conservano baseline e figli. Eq del
recupero usa fattori compatti, inclusi nel piano senza cambiarne il massimo.
La proof passa anche con feature accoppiate f e d·f e selettore corrente
posticipato: tre prodotti per feature, doppio stato esplicito, nessun
cambiamento del massimo globale noto. Il kernel CUDA compila senza spill.
Il primo backend a slot fissi è NO-GO a O=300 con il BMMA: 65,731923 s
parziali. La riscrittura carry/borrow delle primitive campo riapre lo
screen: ricontando range e coefficienti, il lower parziale congiunto è
45,267005 / 52,813136 / 60,657831 s. Controlli host ai bordi e compilazioni
range/BMMA passano; nessuna esecuzione PTX o misura GPU. Il massimo arena
non cambia. La priorità è completare le fasi mancanti nella stessa somma.
Per il ledger RMS è selezionato Γ calibrato reale, confermato da produrre.
Il [preflight](preflight.md#real-calibrated-gamma) identifica gli input,
il raccordo al compilatore e la copertura selezionata. Sul fixture
a scale zero la coda RMS dopo quattro round concessi gratis dà già
70,268864 s: il solo trasferimento del prefisso EXP30 B=16 è NO-GO.
Contatori completi,
picco fisico e harness finale restano aperti. Il NO-GO scalare non si trasferisce
alla contrazione. Il goal locale resta in corso.
Nessun altro census ABI né cambiamento del protocollo è selezionato.

**NO-GO del backend scalare fuso ora implementato:** per il circuito
EXP30 fissato `compile_ratio(14)`, a O=300 i soli coefficienti main-cell
richiedono almeno **67,103981 s** alle condizioni hardware del preflight.
Il conteggio deriva dai cammini del kernel compilato, dopo inline/CSE,
e non usa il fixture RMS non calibrato. È già maggiore di 65 s senza
inferenza, range, PCS, PCG, replay o traffico. Questo esclude quel backend
nella capacità a tre risposte, non ogni backend matematicamente possibile.
Si chiude questa linea senza H100: per riaprirla serve una riduzione
strutturale del lavoro o un'esecuzione aritmetica diversa dimostrata;
ulteriori dettagli allocator/ABI o una misura di banda non possono
rimuovere il lower. Vedi [derivazione e condizioni](preflight.md#no-go-del-main-cell-scalare-fuso)
e [record su SHA pulita](evidence.md#integrated-positive-and-scalar-main-cell-no-go).

**Priorità operativa del proprietario (2026-09-19):** congelati lookup,
GKR e capacity accounting, salvo errori che cambino il picco di almeno
16 MiB o il tempo di almeno 0,5 s. Il gate ridotto è passato: una singola
proof positiva collega getter ordinato, lookup streaming, GKR sourcewise
e WHIR con transcript/MAC originali ideali. Il ledger separa ricostruzione
e consumer senza doppio conteggio; il kernel fuso porta al NO-GO sopra.
Nuovi censimenti
ABI sono esclusi se non chiudono direttamente memoria, tempo o correttezza
di questo percorso. Restano invariati 512 replay, margine di 256 MiB e
assenza di autorizzazione H100/spesa.

**Il trust model autorizzato è ora B12 + EA-LPN-SL-reg\*. Il goal completo
resta aperto sulla fattibilità fisica.** Il proprietario ha accettato la
[premessa concreta](design.md#assumptions-and-component-dependencies)
`Adv_EA-LPN-SL-reg*(675,70778880,353894400,11,Fp;T121,M93,one-leakage)<=2^-80`.
Questa decisione è acquisita; non si richiede nuovamente. Il teorema B12 v1
conserva la sua identità e i propri bound; la sostituzione Dory richiede
ancora il trasferimento compositivo e nativo.

Il tetto preferito rimane **130.000.000 byte alla prima proof**, bootstrap
incluso, e **40.000.000 alle successive**, su C=3 a O=0/150/300. Il nuovo
steering autorizza, se non emerge una soluzione praticabile da 40 MB,
la chiusura analitica della parte proof-size con i lower del corpo
**47.841.180 / 54.868.318 / 61.797.384 byte**. Lo
[screen dopo l'autorizzazione](construction-screen.md#screen-dopo-lautorizzazione-ea-lpn-e-ripiego-sui-byte)
registra questo esito di ripiego: le alternative sotto 40 MB censite
restano fisicamente non selezionabili. I lower omettono GKR congiunti e
fratelli Merkle; non sono upper o dimensioni di prove valide prodotte.
La deroga non chiude PCS streaming, endpoint privati, arena da
6.442.450.944 byte, <=65 s o confronto di lavoro totale.

**Bootstrap:** la candidata Fp6 con guard prima di c, cGGM separato per
nodo, coin ROM e F_EQ a due chiavi costa **61.841.366 byte** per le primitive
censite. La capacità di 70.778.880 righe base supera le 11.466.948 del run
B12 completo; tre righe base formano un Fp3 e il setup si paga una sola
volta. Il corpo B12 fornisce gli intervalli seguenti:

| O | Lower corpo | Upper corpo | Bootstrap censito + corpo |
|---:|---:|---:|---:|
| 0 | 47.841.180 | 65.053.244 | 109.682.546–126.894.610 |
| 150 | 54.868.318 | 78.945.726 | 54.868.318–78.945.726 |
| 300 | 61.797.384 | 92.723.304 | 61.797.384–92.723.304 |

Il margine iniziale di 3.105.462 byte resta da confrontare con completion,
framing/metadata esterni alle primitive e il codec completo. I seed noti
contribuiscono circa 89,9339 bit; con EA-LPN assunta a 80 bit il bootstrap
ha un ledger condizionale di oltre 79,99 bit. La somma prudente con gli
errori completi B12 dà 79,8211 bit soundness e 79,9978 bit ZK, **soltanto
se** il bootstrap realizza l'intera interfaccia MAC richiesta e se ne
scarica la composizione. Non è un nuovo teorema nativo o un bound di tempo.
F_EQ apre le share solo dopo entrambi i commitment; il bound
`1/(|Fp3|-1)` copre qualunque share malevola fissata, inclusa la cancellazione
delle chiavi. La deviazione della vista su rifiuto è già contabilizzata.
Le [derivazioni](construction-screen.md#f_rand-condizionale-e-f_eq-con-due-chiavi-mac)
e i controesempi precedenti rimangono conservati nello screen.

**PCS e memoria:** D36 conserva il solo wire analitico da circa 28,42 MB,
ma richiede 7,834/10,308 TB nei primi/successivi turni. Gli endpoint del
percorso ridotto restano collegati agli originali sotto le proprie premesse;
non forniscono uno schedule canonico. Shout–Akita richiede una PCS privata
nuova: il confronto F_EQ finale non nasconde il transcript pubblico Akita.
I port di [altre PCS private](construction-screen.md#pcs-private-recenti-tre-port-letterali-respinti)
non offrono il seam Fp3–MAC e le risorse complete.

Il nuovo controllo di streaming conserva esattamente l'algebra B12 e
respinge due scorciatoie concrete. Ricostruire l'encoding RS per coset a
righe complete richiede almeno **683 scansioni W** nel metodo esaminato,
prima dell'apertura. Il sumcheck quadratico prefix-first in due passaggi
paga rank×N; troncarlo ai supporti originali è errato. La variante
**suffix-first a 15 bit** conserva invece i selettori durante la prima
contrazione: nel censimento pubblico gli array del riduttore W occupano
**2.898.788.352 byte**, con due letture e **314.498.580.480 aggiornamenti**
nel modello dei due passaggi. Il punto finale viene rimesso nell'ordine
originale per la medesima PCS; il controllo algebrico passa. Sono esclusi
range, PCS, reader fisico e tempo; non è un prover nativo. Le letture
aggiuntive della PCS vanno ora prezzate, senza un tetto assoluto di quattro.
Gli esiti negativi non sono lower universali contro ogni PCS possibile.

Il prossimo avanzamento richiede una costruzione che chiuda insieme
encoding/apertura privata, disponibilità di W/A/KV senza spill, lavoro delle
forme pubbliche e schedule completo entro memoria e 65 s. Accettare la
premessa LPN o il ripiego sui byte non fornisce quella costruzione.
Le materializzazioni dense già respinte restano escluse; il lavoro locale
indipendente è autorizzato, senza spese o esecuzioni pesanti.

Il proprietario autorizza esplicitamente lo
[schedule integrato suffix-first + range + PCS privata](construction-screen.md#schedule-integrato-liveness-range-e-pcs-privata).
Il residuo aritmetico dell'arena è **3.543.662.592 byte**; C può essere
rilasciata prima del secondo passaggio, che usa circa 50 MB di array.
Una cache privata globale dell'istogramma W costa 524.280 byte e consente
di evitare la sua scansione per risposta, con autenticazione sempre fresca.
**Steering del 2026-09-13:** quattro letture W sono solo un obiettivo;
più letture sono autorizzate entro 6 GiB, picco globale <80 GB e <=65 s.
Il checkpoint non è più respinto per le dodici letture, che erano un lower.
La [schedule a finestre Gram private](construction-screen.md#range-con-finestre-gram-private)
supera ora il replay da 56 visite: **26 visite W per il range**, con
**1.596.261.954.560 B di payload** e **640.151.453.695 merge razionali**.
Il nucleo aritmetico confrontabile scende del 48,26%; le finestre variabili
mantengono coefficienti cubici, sfide ed endpoint originali. Il test finito
coincide con il denso. H è privata, al massimo 24.576 B; nessuna nuova
premessa crittografica è introdotta. È un minimo del modello parziale di
moltiplicazioni, non del tempo.
I buffer nominati massimi restano 5,234 GB per il top, 4,027 GB nei livelli
bassi e poi 2,899 GB per linear; non coesistono. Dopo range e linear sono
28 visite W censite, **non** il totale completo con PCS e inferenza.
Il [preflight locale](preflight.md) resta **NO-GO per H100**. La FFT a
blocchi 2048² e il range ora compilano per sm_90 con nvcc 12.9.86:
zero stack/spill ptxas, controlli CPU ridotti passati; nessun tempo GPU.
La compilazione locale usa una correzione dichiarata di quattro prototipi
math nell'header temporaneo per glibc 2.41, senza cambiare aritmetica CUDA.

Il replay completo dei primi oracoli è respinto nelle condizioni del
preflight. La [variante per resti](construction-screen.md#aperture-per-resti-a-cap-fisso)
ora separa payload, suffisso zero pubblico e **gli stessi pad privati**.
Il conto rispetta i chunk contigui del layout nativo. Le specializzazioni
foglie range, sottoalberi zero, Fp3 a sei prodotti e indici FFT riducono
lavoro totale. Algebra finita e compilazione CUDA locale non attribuiscono
credito al refinement su righe/sali/root/NoPeek o al prover completo.

Il nuovo test dominante respinge il getter che rigenera tutta A con MAC
scalari: **>=135,257 s per il solo commit A**, con ceiling espliciti.
Le alternative esatte restano aperte. Range W/A specializzato + FFT commit
A + prime aperture W/tutte A danno lower congiunti parziali **32,722 /
36,085 / 39,685 s** a O=0/150/300. Escludono costi positivi e non sono
upper né certificati <=65 s. Il confronto <=90 s è una possibile futura
deroga da valutare **solo dopo un upper completo**, non autorizzata ora.

Il [ledger dei trace](preflight.md#trace-della-risposta-e-budget-separati)
separa `T_inference`, `T_proof_only` e `T_response_total`: ogni replay A/KV
è lavoro della prova. La ripartizione candidata aggiornata è 1,5 s inferenza e 63,5 s
prova; **non sono upper**. Il vincolo totale resta <=65 s, nessun overlap
presunto. Il proprietario ha autorizzato 65 s totali; nessuna deroga a 90 s.
Arena, HBM, endpoint, trust model e divieto di GPU/spesa restano invariati.
Il [checkpoint riproducibile](evidence.md#dag-condiviso-e-slot-reader-riusato)
registra i nuovi trace e i controlli ridotti; nessuna GPU.

Sono implementati trace locali per 3.471 sorgenti A, 36.171 tessere byte,
liveness di 1.568 nodi per rigenerazione, tutti i 12 oracoli WHIR e PCG.
La fusione per producer/istogrammi nel commit porta i tensori nominati a
52.690.940 B; il nuovo getter ordinato ha dependency cut condivisi
e trace delle finestre, ancora senza adapter numerico nativo completo. WHIR iniziale apre un singleton: una scansione e 128 accumulatori
Fp3 sostituiscono algebricamente il denso per sette round. La candidata
successiva Eq+Pow/PQ ha scratch nominato 507.445.224 B, controlli finiti e
upper di lavoro reference per il precompute. Port nativo, vincolo uniforme
del lavoro completo e liveness fisica restano aperti.

PCG ha reference codec SHAKE H/EAGen con sampler bounded, indici pubblici
distinti, stato dei due ruoli, carry e burn. Il prover è il receiver
punctured, stato persistente allineato 348.372 B. Mancano refinement e
workspace del backend reale; questi check non aggiungono credito al
teorema o al transcript nativo.

Corretto il KV: **901.120 B/token**, non 4.915.200 (incremento di A
attenzione). W+KV450+arena riservati noti sono **68.242.645.504 B**.
Il [getter condiviso e piano integrato](preflight.md#dag-condiviso-getter-ordinato-e-riuso-del-reader)
conservano 61 checkpoint di layer (98.380.800 B), una sola generazione
alla volta. Ogni producer viene valutato una volta per finestra necessaria;
raw, byte siblings e istogrammi vengono emessi prima dell'ultimo consumer.
Sono censite le 26 passate range e la query iniziale di ogni A originale,
con ordine MSB nativo e senza Snapshot/A completi. Restano da portare
le operazioni numeriche e autenticare il collegamento al checkpoint originale.

Il getter condiviso, con commit A a 1.024 replay e FFT a batch intero,
porta il lower parziale della terza risposta a **65,481 s**: NO-GO per
questa schedule sotto i ceiling dichiarati, non per ogni getter/PCS.
La minima alternativa riusa lo slot reader/hash nel commit scatter A,
con hash nelle celle del coset consumato: coset 2^22 e **512 replay**,
S2 sempre 2^22, successori al massimo 2^23. Il ledger con lettura hash separata dà lower parziali **47,498 / 51,975 / 56,751 s**.
Il solo getter ha lower di banda **14,160 / 15,275 / 16,451 s**; il vecchio
budget di 14 s è escluso. Il nuovo budget candidato assegna 17 s al getter,
1,5 s all'inferenza e 46,5 s alle altre fasi, senza credito di overlap.

Il checker nativo degli offset include finestre range 2 GiB/query 256 MiB,
checkpoint, slot PCS/PCG, allocator e fence dichiarate. I massimi nominati
sono **6.087.512.576 / 6.126.837.504 / 6.166.159.104 B**. Il minimo margine
è **276.291.840 B**, appena 7.856.384 B oltre i 256 MiB richiesti. Lo slab
riserva sempre 6.442.450.944 B. Non sono picchi fisici completi: workspace
numerici, hash in place salted, PCG/OT/Fp6 e runtime restano da verificare.

Il [checkpoint locale](evidence.md#dag-condiviso-e-slot-reader-riusato) distingue
conteggi di istanze/indirizzi virtuali, richieste logiche agli operandi e
lower condizionali da HBM fisica e upper completi, tuttora ignoti.
Il [controllo numerico ridotto](preflight.md#getter-numerico-e-hash-nativo-ridotti)
ora ricostruisce ogni byte originale a O=0/2/4 senza Snapshot/A nel getter:
un solo insieme di cut i16 temporanei, KV originali i16 persistenti e
rilascio dopo l'ultimo consumer. Riusa gli operatori interi del preparatore.
Il port canonico numerico e il gather range restano aperti; il collegamento
getter/PCS ridotto è acquisito sotto; i conteggi ridotti non sostituiscono O=0/150/300.
L'hash CPU in-place confronta codec, sali, seek, foglie e root con la MMCS
nativa anche nell'ordine coset `c+Q*j`. Prescan naturale e cursori reali
conservano i rigetti del sampler. Il confronto della catena WHIR ridotta è ora acquisito sotto; il kernel
CUDA e la catena canonica restano aperti. Il ledger include letture, scritture,
compressioni hash e prescan: con la lettura foglie separata i lower parziali
sono **47,498 / 51,975 / 56,751 s**; non cambiano i picchi solo pianificati.
Il successivo lavoro è completare il port del getter e l'integrazione
sourcewise WHIR/PCS, poi scratch PCG/OT/Fp6 e producer GKR/inferenza.
Non manca soltanto un service-rate H100: harness integrato e proposta di
spesa restano non pronti. **Si lavora soltanto sui 512 replay**; la variante
1.024 è chiusa e non viene riesaminata. Il proprietario non richiede più
un upper H100 prima delle misure: richiede costruzione ridotta completa,
conteggi senza ignoti, picco completo con margine e lower congiunto <65 s,
poi microbenchmark isolati, SHA pulita, durata/costo e soglie verificabili.
Questi gate non sono chiusi. Il [replay WHIR ridotto](preflight.md#confine-nativo-whir-e-workspace-da-collegare)
ora include il binding `ObservedMmcs` di C7.1 e coincide con il riferimento
D10 per root, aperture, codec da 2.289.176 B,
transcript e chiusura originale, senza fallback source densi. Il nuovo
handle conserva getter/cache/offset e libera il predecessore dopo le query;
il pad iniziale è condiviso e la riduzione finale in-place evita 128 MiB
aggiuntivi al coset canonico. Restano port accelerato e picco fisico.
H/EAGen hanno confronto Rust/Python e identità Acc/PuncAcc ridotta,
ora con primo split indipendente conforme a Dory, non derivato dall'hash;
Il [Seed6 reale ridotto](preflight.md#seed6-reale-streaming-e-workspace)
collega handshake, 384 OT, COPE AES streaming e K6→Fp3; i rifiuti non
emettono alpha. Il ledger corregge il seed principale a 17.553 righe,
incluse le 2.025 aggiuntive di F_EQ; il secondo ne usa 2.025. Il byte di
direzione nel contesto aggiunge 4 B al budget dei due seed.
Capacità native e rilasci sono censiti; allocator, stack crittografico,
trasporto, lifecycle durevole completo, FS globale e port accelerato restano aperti.
I due seed ora richiedono il seal fresco prima di restituire valori/chiavi;
la handshake v02 respinge la versione precedente prima degli OT. I 40 B
per seed erano già nel budget: nessuna seconda contabilizzazione.
Il consumer guard sui MAC originali passa nel caso reale da nove righe,
con ricetta disgiunta e sfida fissata prima della prova. Il nuovo raccordo
consuma `GuardAccepted`, costruisce cGGM a ruoli separati e usa i MAC
originali per i check split e F_EQ: il caso reale da 25+6 righe accetta
il positivo e rifiuta c/z alterati. Non usa l'oracolo con input congiunti.
Le coin split/F_EQ ora eseguono commit/risposta/apertura e derivano i
coefficienti da uno stream SHAKE, senza array U denso. Anche la sfida guard
ora deriva dal binding sigillato e dalle correzioni congelate, prima della
proof. F_EQ ora possiede gli stati pendenti e li rilascia solo al successo:
il [raccordo EA puntuale](preflight.md#ea-puntuale-dopo-accettazione-f_eq)
produce sei righe base su due blocchi e due MAC Fp3 originali. Il difetto
dei prefissi globali trovato nella versione t=1 è riprodotto e corretto:
il confronto ora controlla anche BAe, non soltanto l'identità MAC.
Il seed EA ora deriva dalle aperture F_EQ verificate e dai relativi blind
freschi già committati, senza parametro prefissato del caller o nuovi
messaggi. Esaurimento o errore terminano il cursore e cancellano lo stato posseduto.
Il [setup su un solo canale](preflight.md#setup-seed6-su-un-solo-canale)
collega ora entrambi i bootstrap, guard, split, coin e F_EQ fino allo stato
EA: sei MAC reali, con beta dai seed originali e cammini campionati.
La geometria è legata alla handshake prima degli OT; il nonce deriva dai
due seed sigillati. L'entry monouso ora riusa il journal B12: burn fsync
prima di RNG, nessun retry/reopen e owner esclusivo fino al rilascio
dello stato EA. Restano composizione ROM del seed, transcript del run,
canale autenticato e collegamento alla proof canonica; non è ancora
il PCG canonico. Le riserve ora riusano le transizioni B12: burn dell'intero
intervallo prima della prima riga, finestra streaming limitata e stop su
errore/panic/esaurimento. La promozione viene dopo fsync, ma la ricevuta
dei test del solo pool è un fixture, distinto dai positivi del wrapper completo. Owner e Audit
restano contati nelle tre risposte (+5.120 B allineati nel piano).
Le finestre ora generano batch di al massimo 4.096 righe: ordinano i
termini pubblici e condividono i cammini della trie, conservando i prefissi
globali. Il confronto reale BAe a sei righe usa 41/36 SHAKE nei due ruoli
anziché 60 sender puntuali. Il controllo al confine 4.096+5/3 non anticipa
la riserva successiva. È esecuzione CPU ridotta, non port CUDA o costo
canonico completo; sorting canonico e stack compilato restano aperti.
Il pool è ora accessibile da altri crate solo con la feature CPU opt-in
`c71-seed6-reference`: conserva owner, OS RNG e limiti di riserva, senza
esporre seed/Delta scelti dal caller. L'algebra Fp3 condivisa è spostata
sotto MAC con reexport compatibili, evitando il ciclo PCG↔MAC. Il test
esterno esegue transfer Fp3 originale; non è ancora la proof composta.
Il corpo PCS/GKR ora accetta `ExactSizeIterator` invece di imporre
`Vec::IntoIter`, mantenendo i controlli di capacità ed esaurimento. È il
passaggio necessario per consumare il pool a batch senza raccogliere tutta
la riserva. Il wrapper interno ora seleziona il riferimento Seed6 opt-in
e riusa Prepare/Verify e promozione B12 con packing lazy. Un tentativo
O=0 ridotto passa con AES reale; alterare il completamento brucia tutta
la riserva senza promuovere A/KV. Il reader ordinato passa ora con Seed6
reale a ell=2 nel solo test ridotto O=0. La continuazione numerica O=2/4
è collegata; restano run ordinato/AES a tre tentativi e port canonico,
senza credito H100.
Il preparatore ordinato usa l'owner pending/accepted comune, W e profili
condivisi e coin PCS OS separati. La storia viene dai soli reader accettati,
con KV Frozen condivisi e controlli di ordine/W/semantica. Il
[confronto numerico O=0/2/4](evidence.md#ordered-numerical-history) non è
un run di tre proof ordinate né un picco fisico.
Il controllo completo ordinato O=0/2 supera il timeout locale di 60 s
dopo la sola prima accettazione; il fallimento è conservato nello stesso
ledger e non autorizza un limite maggiore o un run pesante.
Il [consumer F_EQ ridotto](preflight.md#f_eq-consumer-locale-dei-due-seed-opposti)
usa i due seed a ruoli opposti e fissa commitment prima delle aperture;
correzioni, coin e share ora attraversano due endpoint indipendenti tramite
il framing bootstrap esistente. Nove header da 9 B sostituiscono quelli
prenotati da 6 B: +27 B sul bootstrap. Il setup unico aggiunge altri 45 B
di framing guard/split, senza nuova primitiva.
la riserva consuma il seed e separa coda F_EQ/prefisso guard, cancellando
la vecchia copia della coda. Il test della coin usa randomness riproducibile,
non coefficienti prefissati; non chiude la composizione crittografica.
Il ledger include il lavoro di entrambe le coin, i due passaggi cGGM e
gli stati privati trattenuti fino a F_EQ e il rilascio dopo conversione
positiva, non il picco fisico completo.
Il getter numerico ridotto O=0/2/4 ora apre la root A originale tramite
WHIR; S1 condiviso viene allocato solo dopo le query al predecessore.
Il fold dei successori ora richiede il rilascio dell’handle precedente e
conserva tutta la capacità S1. Il vecchio layout S3 2^24 è NO-GO con questa
capacità; il cap 2^23 paga due letture S2 in più per apertura A e lascia
il massimo integrato nominato, ora 6.166.159.104 B con owner/Audit persistenti. Il merge FFT
odd-log è contato; scatter PCS e fence GPU restano da integrare.
Il [checkpoint RMS](preflight.md#rms-checkpoint-originale-e-coefficienti-gkr-a-memoria-limitata)
usa 2.023.511.878 B con descrittori e riusa lo slot range prima di RNE;
il confronto dei frame originali passa senza A/Snapshot completi.
Il backend GKR denso è NO-GO per memoria. Il prover ora collega replay
Booleano limitato, coefficienti MSB, riduzione degli indici e MAC originali;
il caller usa il checkpoint compatto e assegnamenti pubblici via lookup.
Il binding serializza gli assegnamenti a blocchi di 4 KiB nello stesso
record FS. I confronti ridotti conservano byte della prova, punto, MAC e
transcript del riferimento denso. Il verifier deve rispettare lo stesso
vincolo di memoria: nessuna tabella Eq o selettore proporzionale a N.
Il nucleo fattorizzato del fixture a scale zero conta 377.460 miliardi di
prodotti Fp3, prima di fold/replay. La scalar reference non è una schedule
canonica ammessa; i probe CUDA non danno un lower per un kernel fuso.
L'endpoint byte viene adattato allo stesso transcript con LUT pubblica
lane/byte/nodo da 100.466.688 B al posto dell'albero denso da oltre 210 TB.
Il ledger conta la rigenerazione MSB con pesi condivisi fra quattro figli:
i prodotti Eq diminuiscono del 95,07%, con un solo scratch riusato;
le fold Boolean del GKR usano ora
maschere dei limb mantenendo le addizioni. I confronti con le prove dense
passano. Non si trasformano accessi logici in HBM o prodotti sorgente in
istruzioni H100. Restano lavoro completo, workspace congiunto di
circuiti/prove/correlazioni/allocator e port accelerato. Il caller EXP30
sostituisce il massimo denso NO-GO con un checkpoint da 512 MiB/1 GiB,
rilasciato prima di lookup/GKR; il ledger include le scansioni D aggiuntive.
Il replay GKR riusa input/current/next e li libera prima della LUT byte.
Il lookup conserva cache originali e un cut a 16 foglie; GELU/EXP30 evitano
così gli alberi densi già esclusi dall'arena. EXP30 conta il dominio D/E
completo, inclusi padding causali. Il piano incorpora i payload con cut A
vivi fino all'ultimo consumer; le prove lookup restano riservate tra le fasi.
Il nuovo census nativo GKR/byte misura righe, programmi, prove, triple e
transizioni di buffer, compresi Eq root/leaf. I prefissi e le strutture del
sumcheck prenotano la capacità; il frame FS dei valori viene scritto in
streaming. Allocator, caller e picco fisico completo restano aperti.
Nessuna GPU, spill o spesa autorizzata.

L'estensione nativa resta subordinata: Prepare/prover canonici, percorso
AES composto positivo e refinement dei codec non sono ancora chiusi.
I controlli piccoli in [evidence](evidence.md) e i riferimenti di
[security §§2–3](security.md#2-preparatore-e-macchina-di-accettazione)
conservano il loro perimetro.

## Scope and authorization

Il lavoro locale pertinente è autorizzato dalle richieste del proprietario
del 2026-09-10 e del 2026-09-11 sulla riduzione dei byte, ristrette dallo
steering successivo su memoria globale e dall’aggiornamento esplicito
a 65 s totali del proprietario. Il vecchio limite a 50 s non è più vigente.
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
