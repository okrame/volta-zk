# C7.1 — Goals and current status

Aggiornato al 2026-09-13. [Design](design.md) · [Security](security.md) ·
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
6.442.450.944 byte, <=50 s o confronto di lavoro totale.

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
forme pubbliche e schedule completo entro memoria e 50 s. Accettare la
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
più letture sono autorizzate entro 6 GiB, picco globale <80 GB e <=50 s.
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
upper né certificati <=50 s. Il confronto <=90 s è una possibile futura
deroga da valutare **solo dopo un upper completo**, non autorizzata ora.

Cache h12 iniziale da 188.743.552 B e range cut11/m24 restano coordinati
nell'arena. Lo schedule esplicito senza retention S1 censisce già **97
visite dirette W, 572 A corrente e 34 per vecchia A**, esclusi altri
sumcheck/OOD/switch e W/KV letti dai getter. WHIR committa il successore
prima di interrogare il predecessore; una root cache non evita quei
replay. Gli stati densi sumcheck non entrano e restano fail-closed.

Il getter A/KV ha un contratto streaming con slot proposto 64 MiB e una
specializzazione i16 mediante quattro dot-product int8 esatti. PCG usa
32 B/riga prover; memoization su trie di indici pubblici riduce del 26,83%
l'upper path-step per batch, subordinata al refinement dei due ruoli.
Il commit A iniziale lascia **44.341.480 B** dopo i buffer nominati,
cap proof, getter e trie: mancano ancora maschere, covettore, seed/OT e
allocator. W+KV450+arena riservati noti restano 70.048.981.504 B.
**Picco completo allocato/riservato e upper di tempo restano aperti**;
l'upper di ammissione rimane +infinito. I controlli minimi sono nel
preflight; harness integrato non pronto, nessun H100 o spesa proposti.

L'estensione nativa resta subordinata: Prepare/prover canonici, percorso
AES composto positivo e refinement dei codec non sono ancora chiusi.
I controlli piccoli in [evidence](evidence.md) e i riferimenti di
[security §§2–3](security.md#2-preparatore-e-macchina-di-accettazione)
conservano il loro perimetro.

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
