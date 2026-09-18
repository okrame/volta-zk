# C7.1 — Goals and current status

Aggiornato al 2026-09-18. [Design](design.md) · [Security](security.md) ·
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
nodo, coin ROM e F_EQ a due chiavi costa **61.841.290 byte** per le primitive
censite. La capacità di 70.778.880 righe base supera le 11.466.948 del run
B12 completo; tre righe base formano un Fp3 e il setup si paga una sola
volta. Il corpo B12 fornisce gli intervalli seguenti:

| O | Lower corpo | Upper corpo | Bootstrap censito + corpo |
|---:|---:|---:|---:|
| 0 | 47.841.180 | 65.053.244 | 109.682.470–126.894.534 |
| 150 | 54.868.318 | 78.945.726 | 54.868.318–78.945.726 |
| 300 | 61.797.384 | 92.723.304 | 61.797.384–92.723.304 |

Il margine iniziale di 3.105.466 byte resta da confrontare con completion,
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
S2 sempre 2^22. Il ledger con lettura hash separata dà lower parziali **47,498 / 51,975 / 56,751 s**.
Il solo getter ha lower di banda **14,160 / 15,275 / 16,451 s**; il vecchio
budget di 14 s è escluso. Il nuovo budget candidato assegna 17 s al getter,
1,5 s all'inferenza e 46,5 s alle altre fasi, senza credito di overlap.

Il checker nativo degli offset include finestre range 2 GiB/query 256 MiB,
checkpoint, slot PCS/PCG, allocator e fence dichiarate. I massimi nominati
sono **6.087.369.472 / 6.126.691.072 / 6.166.012.672 B**. Il minimo margine
è **276.438.272 B**, appena 8.002.816 B oltre i 256 MiB richiesti. Lo slab
riserva sempre 6.442.450.944 B. Non sono picchi fisici completi: workspace
numerici, hash in place salted, PCG/OT/Fp6 e runtime restano da verificare.

Il [checkpoint locale](evidence.md#dag-condiviso-e-slot-reader-riusato) distingue
conteggi di istanze/indirizzi virtuali, richieste logiche agli operandi e
lower condizionali da HBM fisica e upper completi, tuttora ignoti.
Il [controllo numerico ridotto](preflight.md#getter-numerico-e-hash-nativo-ridotti)
ora ricostruisce ogni byte originale a O=0/2/4 senza Snapshot/A nel getter:
un solo insieme di cut i16 temporanei, KV originali i16 persistenti e
rilascio dopo l'ultimo consumer. Riusa gli operatori interi del preparatore.
Il port canonico numerico, il gather range e il collegamento al prover
restano aperti; i conteggi ridotti non sostituiscono O=0/150/300.
L'hash CPU in-place confronta codec, sali, seek, foglie e root con la MMCS
nativa anche nell'ordine coset `c+Q*j`. Prescan naturale e cursori reali
conservano i rigetti del sampler. Questo non è ancora un kernel CUDA o
l'encoder/apertura WHIR completo. Il ledger include letture, scritture,
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
Questi gate non sono chiusi. Nessuna GPU, spill o spesa autorizzata.

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
