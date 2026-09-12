# C7.1 — PCS e stato persistente: candidata, non ammissione

2026-09-11. [Stato](status.md) · [Design](design.md) · [Evidenza](evidence.md).

**Disposizione aggiornata al 2026-09-12.** Lo
[steering del proprietario](design.md#owner-authorized-pcsstate-experiment)
ammette soltanto memoria extra globale caricata una volta e riutilizzabile
fra sessioni, con prover completo <=50 s e accessi inclusi. Le cache
dinamiche qui studiate non soddisfano quella concessione: la candidata
densa W/A/KV da 10,31 TB è fermata, anche con una sola sessione alla volta.
I conti e i test sotto conservano il loro perimetro di evidenza; non sono
un piano per continuarne il port. Eventuali componenti riutilizzati in
una costruzione diversa devono prima superare lo screen di fattibilità.

## Screen minimo sotto i tetti assoluti

**2026-09-12 — esito negativo, `credit:false`.** Per «prova» vale il
certificato completo del [contratto](design.md#owner-authorized-pcsstate-experiment),
non soltanto il corpo online delle tabelle seguenti. Capacità esaminata:
**tre tentativi canonici 100+50 a O=0/150/300, 450 token totali**.
Capacità dimostrata sotto tutti i nuovi requisiti: **nessuna**. Non si
estende il profilo a 4.096 token o a nuove sessioni tramite i test ridotti.

Lo [screen eseguibile](../../scripts/c71_pcs_state_screen.py) espone la voce
`feasibility`; il [controllo locale](../../tests/test_c71_pcs_state_screen.py)
verifica i conteggi e i rifiuti. Sono solo interi e geometrie, senza
materializzazioni canoniche, benchmark o nuove implementazioni del protocollo.

### Certificato: il bootstrap della sessione è decisivo

Nel [bootstrap B12](../../rust/volta-pcg/src/c71_bootstrap.rs) `prover_for`
invia al verifier **576 correzioni da 8 byte per riga base**; `verifier_for`
le legge tutte prima della sfida di controllo. Tre righe base producono
una correlazione Fp3. Le correzioni dipendono dalla sessione: AES genera
le foglie ma non elimina quel frame COPE. Non è materiale globale W.

Per il solo P/S RNE v2, `byte_function::required(d)=169+32*d`, anche nel
batch. Sommando sui gruppi senza padding già censiti si ottiene:

| O | Righe Fp3 P/S | Correzioni COPE necessarie al verifier, lower | Tetto certificato |
|---:|---:|---:|---:|
| 0 | 6.582 | 90.989.568 | 130.000.000 |
| 150 | 8.616 | 119.107.584 | 40.000.000 |
| 300 | 8.616 | 119.107.584 | 40.000.000 |

Il lower è `righe_Fp3 * 3 * 576 * 8`: **esclude** sacrifici, OT, check,
seal, framing, tutto il corpo della risposta, le PCS e gli altri consumer.
Sono esclusioni favorevoli alla candidata, non costi assunti nulli.
Con 130 MB la sola quota O=0 non supera più il tetto iniziale; non è
però il bootstrap completo della capacità prenotata.
La somma **329.204.736 > 210.000.000 byte** esclude persino una ripartizione
ipotetica sui tre turni. Il setup unico reale deve invece precedere la
prima risposta e va addebitato lì. Per confronto, provisionare il pool B12
al bound conservativo di 11.466.948 righe dà **53.665.549.985 byte** totali
nelle due direzioni (`233345+4680*n`, seal incluso); non è una misura.

### Memoria, passaggi, traffico e tempo

La variante H100 SXM da 80 GB ha **3,35 TB/s di picco HBM** nelle
[specifiche NVIDIA](https://www.nvidia.com/en-eu/data-center/h100/).
Per l'esterno, PCIe Gen5 offre al più **64 GB/s per direzione**, non 128,
secondo [NVIDIA Hopper](https://developer.nvidia.com/blog/nvidia-hopper-architecture-in-depth/).
Non è disponibile una banda effettiva misurata per questo schedule.
Il picco serve soltanto a un limite inferiore favorevole; come sensibilità
si usa 80% del picco HBM (2,68 TB/s), senza credito di misura. Storage,
accessi sparsi, staging e contesa possono solo peggiorare questi limiti.

Il [prover P/S denso](../../rust/volta-pcs/src/c71_matrix/byte_function/batch.rs)
crea 256 foglie e otto livelli fino alla root per ogni cella byte:
`256+128+...+1=511` coppie da 48 byte. Una sola scrittura per nodo costa
`48*511*N`; gli otto passaggi di costruzione leggono inoltre i figli.
Seguono otto livelli GKR con scansioni/fold dipendenti dalle sfide:
1.560/2.040/2.040 round nei gruppi. Non si può precomputare globalmente
il witness dipendente da A o anticipare quelle sfide.

| O | N celle byte | Sole scritture alberi, byte | Tempo minimo al picco HBM | A 80% del picco |
|---:|---:|---:|---:|---:|
| 0 | 23.135.780.864 | 567.474.433.032.192 | 169,40 s | 211,74 s |
| 150/300 | 24.142.413.824 | 592.165.126.275.072 | 176,77 s | 220,96 s |

Il gruppo maggiore D34 trattiene **421.387.831.345.152 byte** di soli
alberi, contro arena 6.442.450.944 e HBM totale <80.000.000.000 byte.
Questa materializzazione è esclusa anche processando i gruppi in sequenza.
I limiti di tempo assumono persino una memoria abbastanza grande: sono
una seconda ragione di rifiuto, non uno schedule hardware realizzabile.
Il nucleo cubico conserva circa **200,59 / 209,31 / 209,31 mila miliardi
di moltiplicazioni Fp3 espresse nel codice**, oltre alla costruzione alberi;
non sono istruzioni GPU né operazioni tensor FP8. Letture, copie dei figli,
fold, hash, PCS, PCG, inferenza e serializzazione restano da aggiungere.
Il tempo completo non ha upper finito verificato; il lower delle sole
scritture basta a respingere la variante densa. Non serve misurarla.

| Linea esaminata | Memoria globale / dinamica | Esito minimo |
|---|---|---|
| KV cumulativo, W a tre esposizioni | W conservato 2,886 TB, con pad a lifetime finito; ogni A densa 1,443 TB, predecessore e successore vivi | Esclusa: A fuori memoria ordinaria, RNE dense e COPE sopra i tetti |
| W e KV rinnovati separatamente | W rinnovato è anch'esso stato specifico; fino a 8,66 TB conservati | Esclusa: memoria dinamica e stessi costi RNE/COPE; upper del solo corpo 41,14 MB non certifica il tetto |
| Stato unico W/A/KV | Due S dinamici, 10,31 TB; W installato separato al primo turno | Esclusa: memoria dinamica e stessi costi RNE/COPE |
| Sola trasformazione privata globale di W, mantenendo i consumer correnti | Il solo codeword W non mascherato della geometria ridotta è 2.199.023.255.552 byte, oltre a W/runtime; A, maschere fresche e workspace restano dinamici | Non selezionabile: non risolve COPE o RNE/A; rigenerare pad e Merkle per sessione non è precaricamento globale |

Per l'ultima linea, anche **una sola lettura completa** di quel codeword
esterno richiederebbe almeno 34,36 s a 64 GB/s. Nello scenario ottimistico
di 50 GB/s sostenuti (78,125% del picco, non misurato) richiede 43,98 s:
restano **6,02 s** per tutto il resto. Con due letture sono già 87,96 s.
Se si riservano esplicitamente 15 s al lavoro restante, il budget IO è
35 s, ossia al più 1,75 TB a 50 GB/s: nemmeno una lettura vi entra.
Questa riserva è un criterio di screen, non una previsione del costo crypto.
Un canale esterno diverso o accessi parziali richiederebbero evidenza propria;
non sono assunti disponibili. Il rifiuto COPE/RNE non dipende da PCIe.

### Disposizione e riuso

**Nessuna candidata esaminata è plausibile nel contratto completo.**
Si ferma il port delle costruzioni dense e la loro ottimizzazione wire.
Setup, caricamento globale una tantum, bootstrap per sessione, replay e IO
restano nel confronto di lavoro su ogni prefisso; non è dimostrato lavoro
totale non crescente, neppure contro una baseline fisicamente esclusa.

Si possono riusare semantica intera, endpoint originali, codice di framing
e identità MAC nei loro perimetri. Conservare un calcolo deterministico
privato di W/Γ può evitare lavoro ripetuto; non concede il riuso delle
maschere PCS o delle correlazioni VOLE. La traslazione B12 di
[security §5](security.md#5-simulatore-congiunto-e-nopeek) copre una nuova
installazione e un'unione finita di esposizioni, non sessioni illimitate.
Le nuove schedule richiedono i propri bound composti ROM/ZK e risorse.

Il collo di bottiglia è doppio: **comunicazione delle correlazioni fresche**
e **materializzazione/lavoro dei consumer e PCS dinamici**. Una nuova PCG
a comunicazione minore e un algoritmo senza tali alberi/codeword sarebbero
cambi di costruzione da sottoporre prima allo screen, non ottimizzazioni
ammesse per ipotesi. Non si afferma un'impossibilità per ogni protocollo:
si chiude negativamente questa selezione senza approfondire una nuova
candidata priva dei costi decisivi.


## Risultato e criterio del proprietario

La variante studiata combina PCS con parametri ridotti, RNE in gruppi senza
padding aggiunto e KV cumulativo nel nuovo snapshot. Il solo KV cumulativo
non risolve il lifetime di W: il commitment B12 installato ha tre esposizioni.
Le prime due costruzioni restano **non selezionate**:

| O | B12 attuale, upper | KV cumulativo, W a tre esposizioni | KV e W entrambi collegati al predecessore |
|---:|---:|---:|---:|
| 0 | 65.053.244 | 27.391.328 | 26.669.152 |
| 150 | 78.945.726 | 34.647.176 | 41.135.340 |
| 300 | 92.723.304 | 34.647.176 | 41.135.340 |
| PCS per risposta | 2 / 3 / 4 | 2 / 3 / 3 | 2 / 4 / 4 |

Sono **upper condizionali del wire della risposta**, con corpo, RNE, range,
maschere, sali, frontiere Merkle massime, header, frame e chiusura. Non sono
certificati Gemma validi misurati. I lower corrispondenti della seconda
variante sono 17.840.832 / 26.813.068 / 26.813.068 byte e conservano le
omissioni del lower B12: GKR congiunti e hash fratelli. Il lower non è un
obiettivo raggiunto. Questi upper escludono bootstrap/offline: non sono upper del certificato
completo sotto il contratto corrente. Il loro costo obbligatorio è contato
nello screen sopra, senza modificare i record storici.

La seconda variante evita anche il budget di maschere W lineare nel numero
di tentativi pianificati, ma paga una PCS W aggiuntiva dopo il primo turno.
Non è dimostrato un minimo globale: lo screen visita soltanto 60 geometrie.
Il minimo wire della famiglia usa 448 query; il componente nativo studiato
ne usa 456. Il margine di questo screen PCS non sostituisce il bound completo.

Una terza candidata, [stato unico W/A/KV](#stato-unico-wakv-con-installazione-separata),
proietta **26.636.236 / 28.422.476 / 28.422.476 byte** completi, pagando
anche il collegamento al W installato prima del primo prompt. Usa due PCS
per risposta e riduce i termini delle query nei tre prefissi confrontati.
Il dominio D36 aggiunge però padding e lavoro nei sumcheck iniziali.
Era la pista da verificare per il vincolo congiunto byte/lavoro; ora è
fermata dal vincolo di memoria globale, non è ammessa.

**L'obiettivo di riduzione resta aperto; la selezione corrente è negativa.**
Le tabelle seguenti conservano derivazioni componenti, non un piano di port
o una candidata che abbia superato lo screen.

## PCS: cambiamento circoscritto

Si riusano l'IOP CFW, il consumer claimless, la chiusura sul MAC originale,
Goldilocks/Fp3, Merkle salato e la disciplina FS B12. La fonte primaria è
[CFW 2026/391](https://eprint.iacr.org/2026/391), già conservata come
[Markdown AnyDoc](../../sota/2026-0391-zero-knowledge-iopps-constrained-interleaved-codes.md).
La fonte dimostra HVZK dell'IOP; il trasferimento al verifier malevolo/FS
rimane quello da ricomporre, non una proprietà acquisita citando il paper.

| Parametro | B12 | Candidata |
|---|---|---|
| Query per oracolo/maschera | 512 | 456 |
| Fold D34/D35 | 7, poi 2 | 6, poi 4 |
| H per M coefficienti e r pad | nextpow2(8(M+r)) | nextpow2(4(M+r)) |
| r iniziale | 1536 | 1368 per tre esposizioni; 912 per due |
| r successivo | 512 | 456 |
| ell comune a tutte le maschere della PCS | 2048 | r iniziale + 1 |
| Dominio maschere | 32768 | 8192 |

`H>=4(M+r)` implica `H-(M+r)+1>3H/4`: rimane la premessa MCA
`3*tau<d`, con tau=H/4, senza congetture di lista. Restano dominio
Goldilocks <=2^32, codice comune delle maschere, pad sufficienti per
l'unione delle esposizioni e una coordinata per l'OOD. Il censimento usa
gli errori dei veri blocchi B12, incluso
`(1-1/(4G))^(G*t)` per query indipendenti dei gruppi; non sostituisce questo
termine con `(3/4)^t`. Arrotonda i razionali verso l'alto a 256 bit.
Il termine PCS isolato `Q* max(delta_blocco)` è sotto 2^-87; non è la
soundness completa della nuova schedule.

Le PCS della prima variante hanno intervalli wire:
W/D35 5.157.568–7.932.608, A/D34 4.434.784–7.136.864 byte.
Il codec canonico con questi parametri è controllato con fixture sintetiche.
Il test positivo su D12 verifica invece PCS effettive, MAC originale,
digest FS, troncamento e target falso, per tre/due esposizioni della root.
Non esegue una prova linear/Gemma completa. Il primo tentativo di test D10
con fold 1→4 è stato respinto da `RateGrowsDomain`; D12 usa 4→4. Non si
attribuisce il successo D12 alla geometria D10 respinta.

## KV cumulativo e, separatamente, rinnovo W collegato

Preparare A_j prima delle sfide, includendo una copia del KV già accettato
oltre alle sorgenti correnti. Ciascuna copia ha un layout pubblico: layer,
K/V, posizione, head, canale e byte. Il KV dell'ultimo token è incluso.
Il verifier conserva soltanto il predecessore completo necessario alla
transizione e l'identità dell'installazione; non importa ricevute del peer.

Dopo C_Aj, campionare un punto r sul vettore byte concatenato del KV
precedente. Autenticare una sola volta z, valutazione del vecchio KV, e
inserire **lo stesso MAC** in entrambe le PCS, con le rispettive forme:

```text
L_prev(r, A_(j-1)) = z = L_copied_prefix(r, A_j).
```

Un'alterazione fissata prima di r dà un polinomio multilineare non nullo;
la perdita interattiva è al più d/q. Nel ROM occorre addebitare il nuovo
blocco ai prefissi/candidati globali, insieme a PCS e MAC. Gli endpoint
QK/PV leggono tutto il KV da A_j; la coda nuova viene ancora dai produttori
originali. Non basta un hash del KV o un MAC libero. L'induzione same-W/KV
usa le sole promozioni dopo verifica completa; abort e fallimento terminano.

Il vecchio KV aggiunge 0 / 344.064.000 / 688.128.000 byte logici ad A.
I live totali diventano 13.154.672.538 / 14.678.384.538 / 16.202.096.538:
ancora D34 per questi tre contesti. Copia, getter, forme e range non sono
gratuiti. Anche conservando pagine immutabili con alias, letture e lifetime
vanno conteggiati e il predecessore resta vivo fino alla promozione.

Per la seconda variante, dopo il primo turno preparare anche un commitment
W_j fresco e indipendente da Delta. Un secondo MAC condiviso lega una
forma casuale dell'intero W_j a W_(j-1), padding incluso. I produttori
usano W_j; la catena verificata mantiene l'identità del W installato.
Ciascuna root W ha al più due esposizioni: uso corrente e collegamento
al successore. Non riutilizzare correlazioni, pad o maschere di proof.
La tabella paga entrambe le PCS W, il nuovo MAC/frame e 128 byte riservati
ai metadata delle root di lavoro, oltre al collegamento KV. Sono riserve
di uno schema proposto, non framing nativo completo già implementato.

Il numero di PCS diventa costante. Con un blocco nuovo fissato, la loro
geometria e quella dei sumcheck crescono con il logaritmo dei domini al
crescere della storia. **Non è una prova di lifetime illimitato:** capacità
AES, query RO, risorse delle riduzioni, layout e cap dei kernel richiedono
un profilo finito esplicito. Non si estrapolano i tre test a 4.096 token.
Se crescono invece i token nuovi, la lista dei token impone già almeno
4 byte per token nel codec corrente: i byte completi non sono sublineari
in quella quantità, né nel totale cumulativo di tutte le risposte.

## RNE: eliminare il padding aggiunto prima di confrontare il lavoro

Il batch a due gruppi precedente aggiungeva 2.634.022.912 / 1.627.389.952 /
1.627.389.952 celle byte, ciascuna con 256 foglie P/S. È un aumento reale
del lavoro della sua implementazione densa, non compensato automaticamente
dalle 839.615–841.535 righe Fp3 eliminate.

`unpadded_groups` ordina stabilmente per dimensione e riempie blocchi
diadici esatti. Ogni richiesta originale appartiene a un solo gruppo;
non spezza endpoint o tabelle e non aggiunge celle:

| O | Bit dei gruppi | Byte P/S con frame |
|---:|---|---:|
| 0 | 34,32,30,29,25,24 | 197.100 |
| 150/300 | 34,32,31,28,27,26,25,24 | 258.000 |

La versione 2 passa il peso pubblico L direttamente al primo livello
GKR, eliminando il precedente sumcheck quadratico e il suo MAC della root.
Risparmia altri 17.016 / 22.208 / 22.208 byte e 528 / 689 / 689 righe
Fp3 rispetto ai gruppi v1. Per risposta spariscono rispettivamente
23.135.780.858 / 24.142.413.816 iterazioni quadratiche. I byte delle
versioni precedenti rimangono nei loro record, non vengono corretti.

Il nucleo condiviso è sempre `range::prove_tree` con otto livelli cubici:
il primo usa L, gli altri i normali pesi eq. Per N celle e K controlli
separati, le coppie sono `255*N-8*K`; con G gruppi sono `255*N-8*G`.
Le coppie aumentano dunque di 7.088 / 7.072; i round cubici scendono da
197.864 / 198.344 a 1.560 / 2.040. Il numero di foglie e nodi P/S rimane
quello separato. Non si nasconde il piccolo aumento delle coppie.

Lo screen conta anche le espressioni Fp3 del nucleo: per coppia 27 mul e
23 add/sub nei coefficienti, più 5 mul/10 add/sub nei fold; per round
8 mul/17 add/sub; per livello 17 mul/20 add/sub; ogni controllo prodotti
ha 24 triple a 6 mul/4 add/sub. La costruzione eq usa il seme lambda^j,
senza moltiplicare nuovamente ogni cella. In questo perimetro, contro
le RNE separate si eliminano 1.579.292 / 1.579.272 mul e
3.323.878 / 3.323.908 add/sub. Il risparmio del sumcheck separato
confronta invece v2 con v1.
Sono conteggi delle espressioni del codice, non istruzioni CPU/GPU.

**Restano esclusi** da questi numeri tabelle, aggregazione caller,
trascrizione FS, memoria/IO e PCS. Il confronto completo deve pagarli;
non si assegna credito di lavoro totale o di sicurezza dal solo nucleo.
Il kernel condiviso conserva il percorso ordinario con L=eq e la variante
resta test-only. La dimostrazione di composizione del peso L è aperta.

## Lavoro completo: confronto richiesto, ancora non scaricato

Lo [screen eseguibile](../../scripts/c71_pcs_state_screen.py) conserva
`full_prover_work:null` e `full_work_nonincrease_verified:false`.
Conta geometrie logiche per encoding e butterfly radix-2, distinguendo
campo base ed estensione. Per W con tre esposizioni l'encoding iniziale
scende da 549.755.813.888 a 274.877.906.944 celle base e da
8.796.093.022.208 a 4.398.046.511.104 butterfly. A dimezza anch'essa
l'encoding iniziale. **Non sono tempi o conteggi completi del backend.**

Il confronto necessario è per ogni prefisso della stessa conversazione:

```text
setup + tutti i commit/rinnovi + inferenza + preparazione witness
+ RNE/GKR/range + PCS/fold/FFT/hash + PCG + replay
+ serializzazione + scritture/letture/trasferimenti delle cache.
```

Il prover attuale rimaterializza la root in `prove_pcs`, oltre a crearla
nel setup. Nel run di T risposte ciò dà 1+T encoding iniziali W e
T+T(T+1)/2 encoding A. La variante con entrambi gli stati mobili, senza
riuso dei dati di commit, ne dà 3T-1 per ciascuna famiglia: **W aumenta**
da 4 a 8 esecuzioni a T=3, pur con encoding più piccolo. Non basta
mostrare il costo di una singola PCS. Anche gli hash/sali per riga possono
avere un rapporto diverso dai byte dei codeword.

L'interpretazione precedente della memoria fuori H100 ha motivato lo studio
della conservazione dei dati iniziali di commit fino all'ultimo consumer.
Lo steering del 2026-09-12 esclude questa cache quando dipende dalla sessione;
copie, trasferimenti, nuovi pad, proof fresche e creazione non sono gratuiti.
Il costruttore C71 ordinario
continua a rimaterializzare; il nuovo costruttore con conservazione è ora
collegato al batch lineare e usato dalla transizione sperimentale piccola.
Rimangono invariati H100, arena, trust model e assenza di autorizzazione
a run pesanti/provider. I dati canonici non vengono materializzati localmente.

I seguenti obblighi restano non scaricati; il rifiuto nello screen sopra
non autorizza a proseguirli su questa costruzione: lavoro completo contro
la baseline, composizione ROM/ZK/risorse, routing e certificato canonico valido. I lemmi `Mac.Valid.add/smul/sum` e l'induzione KV già
citati in [security §6](security.md#6-risorse-riuso-formale-e-confine-runtime)
supportano le identità; non dimostrano da soli questa nuova costruzione.

## Stato unico W/A/KV con installazione separata

La terza candidata mantiene una root W iniziale, fissata **prima del primo
prompt**, e crea per ciascuna risposta uno stato privato immutabile:

```text
S_j[D36] = W_j[D35] || A_j_con_KV_precedente[D34] || zero[D34].
```

W contiene gli i16 simmetrici del modello; A contiene byte e le sorgenti
previste dalle ricette. Non si applica lo stesso alphabet ai due blocchi.
Le forme W originali restano all'offset zero, le forme A/KV ricevono
l'offset pubblico 2^35. Range W e range A mantengono domini D35 e D34:
i loro MAC terminali entrano nel batch lineare della stessa root S.
Non si sostituisce il range i16 con quello byte. Il quarto finale è
esplicitamente zero e richiede una forma casuale con target noto zero;
non è witness libero, né un costo di elaborazione omesso.

Al primo turno le PCS sono **W installato + S_0**. Dopo entrambe le root,
un MAC originale condiviso collega una forma casuale di tutto W installato
al blocco W di S_0. Omettere questa prima PCS cambierebbe la garanzia in
«W scelto dopo il prompt»: l'upper di 20,33 MB ottenuto omettendola non
è un risultato della candidata. Dal secondo turno si aprono soltanto
**S_(j-1) + S_j**. Le forme di uguaglianza collegano W e tutto il KV
precedentemente accettato, incluso l'ultimo token, con gli stessi MAC
nei due batch. Le altre sorgenti A correnti sono vincolate dall'inferenza,
non dall'uguaglianza col vecchio snapshot. Le root precedono le nuove
sfide e la promozione avviene soltanto dopo tutti i controlli; abort termina.

Questo dà l'induzione same-W/KV interattiva condizionata alla correttezza
delle PCS, delle forme e dei consumer originali. Il test finito verifica
il trasporto dei MAC sotto gli offset e copre alterazioni di W iniziale,
ultimo KV e padding. Non è una prova ROM/ZK: nuovi blocchi FS, simulatore,
esposizioni congiunte e risorse della riduzione restano da comporre.

| PCS | Dominio | Esposizioni | Primo fold, poi 4 | ell | Intervallo wire |
|---|---:|---:|---:|---:|---:|
| W installato | D35 | 1 | 7 | 457 | 4.000.792–6.323.480 |
| Stato S | D36 | 2 | 8 | 913 | 5.288.656–7.990.736 |

Entrambe usano 456 query e rate factor 4; i domini iniziali sono 2^31,
entro la two-adicity Goldilocks. Le maschere restano comuni dentro ciascuna
PCS. Si confrontano le forme native del codec con questi parametri, ma
il dispatch C71 selezionato resta D35/D34 e **non ammette S/D36**.
Il positivo PCS piccolo aggiunge W a una esposizione e D13 con primo fold 5.
Il nuovo [percorso di transizione](../../rust/volta-pcs/src/c71_matrix/gemma/native/joint_state.rs)
li collega a range, MAC originali e promozione su sorgenti sintetiche;
il suo perimetro è descritto sotto, separato dall'inferenza Gemma.

Il conto completo sostituisce le quattro PCS mobili con le due S,
mantenendo prudenzialmente i loro frame e la riserva metadata di 128 byte.
Al primo turno aggiunge la PCS di installazione e 36 byte per il link.
I gruppi RNE senza padding aggiunto e tutti gli altri consumer restano
nel conto. Ne risultano gli upper 26,64/28,42/28,42 MB; non si eliminano
setup, bootstrap o il costo della root di installazione dal lavoro.

Per un prefisso di T risposte si creano una volta W installato e T stati;
le PCS sono una su W e 2T-1 su S. Il numero di root aperte per risposta
è costante, entro la capacità finita dichiarata. Il payload conservato
prima della prima promozione è 7.834.022.682.560 byte; successivamente
due S sommano **10.307.925.245.888 byte**, circa 9,375 TiB fuori H100.
Valgono le stesse esclusioni di allocator, workspace e trasferimenti
del conto precedente. Nessuna allocazione canonica è stata eseguita.

| Prefisso | Termini covettori B12 | Termini stato unico | Celle sorgente sumcheck B12 | Celle stato unico |
|---:|---:|---:|---:|---:|
| 1 | 274.877.841.408 | 261.133.996.032 | 51.539.607.552 | 103.079.215.104 |
| 2 | 641.381.629.952 | 522.267.992.064 | 120.259.084.288 | 240.518.168.576 |
| 3 | 1.099.511.365.632 | 783.401.988.096 | 206.158.430.208 | 377.957.122.048 |

Anche le geometrie DFT iniziali e fresche diminuiscono in ogni prefisso;
la tabella mostra il costo in aumento invece di compensarlo con un peso
arbitrario. Le celle sommano i domini di ingresso alle PCS, non tutte le
operazioni dei sumcheck lineari/PCS. Il kernel dei covettori è ancora t*M:
questa riduzione finita non scarica il contratto uniforme delle sorgenti.
Contabilità completa, schedule fisico e positivo canonico restano necessari.

### Transizione nativa piccola con range e dati PCS conservati

`joint_state.rs` è test-only e riusa `Batch`, `Writer`, `Reader`, range e
batch lineare del percorso nativo. Il profilo locale è W/D12 a una
esposizione e S/D13 a due; ogni S contiene W, A/D11 e un quarto zero.
Le sorgenti sono sintetiche: non c'è Prepare/inferenza o batch RNE in
questa esecuzione, né una nuova ammissione AES o del profilo canonico.

Il trasporto contiene un header di dominio sperimentale, i link W/KV,
range i16 simmetrico W e byte A, le due prove lineari/PCS e il record finale.
Ogni record passa nello stesso FS. Il verifier ricostruisce i link dal
proprio slot e predecessore; i valori condivisi sono autenticati una sola
volta e consumati originali nei due batch. La forma del quarto zero usa
il target noto zero. I range leggono viste dello snapshot e restituiscono
forme che vengono traslate agli offset di S, senza creare altre root.

Il wrapper `Model::new_with_retention` mantiene i dati iniziali tramite
`Arc` immutabile; `prove_pcs` usa il kernel di apertura conservata, senza
rimaterializzare. I cloni condividono quei dati, non rinnovano pad o
esposizioni. Le proof e i sali freschi rimangono indipendenti. Il costruttore
ordinario conserva il percorso precedente e il dispatch D36 resta chiuso.
Il percorso positivo prepara un successore per volta e rilascia il vecchio
oggetto dopo la promozione. Le copie delle viste range del test non sono
uno schedule fisico ammesso e vanno considerate nel confronto completo.

Il verifier riserva l'intera capacità prima del parsing, conserva il
predecessore in caso di errore e termina su errore o esaurimento. Mantiene
anche l'insieme delle root già viste per rifiutare il riuso di una root
ritirata: sono identificatori persistenti lato verifier, non nuove aperture
o una lista trasmessa nel certificato. La loro memoria/lavoro non sono zero.
I replay negativi del verifier sono controfattuali di una sola emissione,
non esecuzioni del prover che riusano le correlazioni.

### Inferenza completa ridotta con RNE raggruppate

Il [confronto test-only](../../rust/volta-pcs/src/c71_matrix/gemma/native/joint_inference.rs)
esegue la stessa inferenza ridotta B12: un layer, hidden/vocabolario 2,
prompt 1 e generato 1, O=0/2/4. Confronta esattamente pesi, token e intero
snapshot A prima del nuovo packing. Prepare possiede sempre i valori;
il callback cambia solo la costruzione finale della sorgente, evitando
un commitment A provvisorio. Prover e verifier condividono il corpo B12
attraverso RMS, RNE, lookup, gate, RoPE, QK/PV, softmax, argmax e range.

W/D12 installato precede il prompt. Ogni S/D13 contiene W, A/D11 e un
quarto zero; i vecchi KV sono byte i16 nel bank A a offset 1536, oltre
alle sorgenti correnti. Le forme QK/PV dei KV usano gli stessi MAC
originali, combinati pubblicamente fra bank e K/V correnti. Il link al
predecessore confronta tutte le parole KV già accettate, compreso l'ultimo
token emesso, sotto range byte. Una sola uguaglianza W collega W installato
alla prima S e poi ciascun predecessore al successore. Le forme W/A sono
traslate nel batch finale S, senza cambiare i target originali. Header,
framing, link, entrambe le PCS e completion entrano nello stesso FS.

Le sette riduzioni RNE originali del frame 3 rimangono; i relativi controlli
byte usano tre gruppi da 128/64/32 celle: **224 celle in entrambi i percorsi**.
Il punto di ogni gruppo viene riportato alle forme della medesima A tramite
prefisso e offset pubblici. I controlli RNE interni agli altri consumer
rimangono quelli B12, come nel conto canonico delle 892 RNE originali.
La cardinalità dei gruppi è derivata dal verifier. Tutti gli endpoint
ritornano alla S effettiva, non a un commitment virtuale aggiuntivo.

| Turno | Certificato B12 circa | Certificato con stato unico circa | PCS B12 / candidata | Righe Fp3 candidata |
|---:|---:|---:|---:|---:|
| 1 | 7,74 MB | 5,01 MB | 2 / 2 | 86.845 |
| 2 | 10,94 MB | 5,44 MB | 3 / 2 | 87.323 |
| 3 | 14,15 MB | 5,45 MB | 4 / 2 | 87.824 |

I [byte del record pulito](evidence.md#joint-state-complete-bounded-inference-comparison)
comprendono l’intero certificato valido sul **grafo ridotto**, con sali/sfide
freschi e frontiere Merkle variabili. Non sono i 26,64/28,42/28,42 MB
canonici: questi restano upper condizionali del codec. Il totale ideale
è 261.992 righe Fp3 contro 265.713; il bootstrap reale non viene eseguito.
La riduzione delle correlazioni non compensa automaticamente altre operazioni.

Il negativo modifica la K dell'ultimo token accettato prima di Prepare:
l'intera nuova inferenza e il suo certificato sono prodotti, ma Verify
rifiuta e brucia la riserva senza promuovere. I replay diagnostici di
troncamento tardivo e cardinalità RNE errata sono controfattuali della
singola emissione; non rinnovano correlazioni o esposizioni. La cache
PCS dell'installazione viene rilasciata dopo la prima promozione; poi si
mantengono solo predecessore e successore. Le copie delle viste e gli
snapshot numerici storici del runner rimangono espliciti costi locali,
non uno schedule fisico ammesso per la H100.

Questo controllo composto scarica la lacuna di integrazione **sul grafo
piccolo**. Non scarica il lavoro totale, il routing D36, l'esecuzione
canonica/AES, i bound ROM/ZK della nuova costruzione o una crescita
sublineare oltre la capacità finita. La composizione scientifica deve
ancora includere le uguaglianze fra sorgenti, il batch RNE e le risorse
della foresta PCS prima di trasferire garanzie di sicurezza.

## Dati iniziali conservati: uguaglianza della prova e lavoro evitato

`HidingWhirProver::prove_claimless_retained` prende un riferimento immutabile
al `HidingWhirProverData` già restituito da commit. Riusa il motore ordinario:
messaggio, randomness e Merkle iniziali non vengono clonati o ricostruiti.
Le prove fresche, gli switch e i loro coin restano necessari. Il ramo
ordinario continua a possedere e rilasciare il Merkle iniziale al primo
switch; solo il nuovo ramo mantiene il riferimento alla cache del caller.

**Equivalenza circoscritta.** Fissare i coin modello e una sequenza ammessa
di target, nonce, key e coin di proof. A ogni apertura il commit ripetuto
del prover precedente ricostruisce lo stesso messaggio, pad, codeword,
salt e albero. Il nuovo percorso legge proprio quell'oggetto già creato
nel setup e assorbe la stessa root, allo stesso punto di FS. Ogni passo
successivo riceve gli stessi valori e coin nel medesimo motore; produce
quindi gli stessi byte, sfide e residui. L'induzione vale anche sui prefissi
interrotti. Per questa sola sostituzione di storage non nasce un evento
di soundness/ZK aggiuntivo. Restano le premesse B12, l'indipendenza del
setup da Delta e il budget di esposizioni imposto dal caller. Non è una
dimostrazione del rinnovo W, del nuovo batch RNE o del protocollo mobile.

Il test `c71_pcs_retained_commit_data_preserves_wire_and_removes_rebuild`
confronta due esecuzioni con lo stesso tape per ciascuna esposizione,
verifica PCS/MAC e digest FS e controlla l'identità byte-per-byte.
Il trace del DFT perde esattamente il primo encode e conserva tutte le
chiamate successive nelle stesse dimensioni. Gli indirizzi di messaggio,
pad, matrice codificata, sali e root del Merkle rimangono invariati.
I payload conservati D12 sono 3.727.328 byte per B12 e 1.984.480 per
la candidata a due esposizioni; le capacità dei buffer coincidono in
questi casi. Header Vec e allocator restano esclusi da quei payload.

Il caso D10 senza switch viene verificato anche dal kernel, ma il codec
C71 rifiuta il suo oracolo finale base anziché cubico. Il test conserva
quel rifiuto e confronta il payload serde completo e FS; non attribuisce
byte nativi ammessi a quel caso e non allarga il parser C71.

Lo screen ora conta setup e ogni apertura sull'intera conversazione:

| Prefisso | Commit iniziali B12 W/A | B12 con dati conservati W/A | Stato mobile con dati conservati W/A | PCS B12 / mobili |
|---:|---|---|---|---|
| 1 | 2 / 2 | 1 / 1 | 1 / 1 | 2 / 2 |
| 2 | 3 / 5 | 1 / 2 | 2 / 2 | 5 / 6 |
| 3 | 4 / 9 | 1 / 3 | 3 / 3 | 9 / 10 |

I dati necessari per ogni nuovo commitment mobile sono creati e contati
una volta, senza spostarli in un setup gratuito. I dati iniziali conservati
per due W e due A della candidata sommano **8.658.655.936.384 byte** di
payload prima della promozione (circa 7,875 TiB). Comprendono messaggi
Fp, codeword, randomness, sali e tutti i digest; escludono strutture,
allocator, runtime, proof fresche e staging. È una proiezione di storage
privato fuori H100, non RAM disponibile o un picco hardware misurato.

**Costo scoperto nel resto della PCS.**
`SelectStatement::combine_packed` costruisce i covettori delle query con
un prodotto scalare di t termini per ciascuna delle M celle. Lo split
riduce la memoria temporanea, non il lavoro t*M. Per i tre prefissi,
la somma di questi termini è:

| Prefisso | B12 | Stato mobile, fold iniziale 6 |
|---:|---:|---:|
| 1 | 274.877.841.408 | 391.700.994.048 |
| 2 | 641.381.629.952 | 1.175.102.982.144 |
| 3 | 1.099.511.365.632 | 1.958.504.970.240 |

Questa voce aumenta e non sparisce conservando il commitment. È contata
separatamente dai DFT, non sommata come se ogni termine avesse costo
identico a una butterfly o a una moltiplicazione Fp3. La clausola del
design che vieta di nascondere t*M nel trattamento delle sorgenti non
è quindi scaricata da questo percorso denso. Il confronto completo deve
includere questi covettori, il primo livello RNE pesato, le forme di link,
il KV e lo schedule fisico della cache. Rimane `full_work_nonincrease_verified:false`.

## Esito fisico D36 nel backend corrente

Il wire da 26,64/28,42/28,42 MB non rende eseguibile la candidata. Il
`HidingWhirProverData` canonico occupa 2.680.060.059.616 byte per W/D35 e
5.153.962.622.944 per S/D36: W+S al primo turno sono
7.834.022.682.560 byte, mentre due S sono 10.307.925.245.888 byte. Sono
1.216x e 1.600x l'arena da 6.442.450.944 byte. `Resident` rimuove soltanto
il messaggio host; `retain=false` ricostruisce la stessa matrice e lo stesso
Merkle durante l'apertura, quindi nessuna delle due opzioni riduce il picco.

Il limite precede anche MMCS/DFT: il batch lineare D36 alloca `form` e
`weights`, due vettori Fp3 da 1.649.267.441.664 byte ciascuno. Il range W
materializza 3.298.534.883.280 byte e quello A 1.649.267.441.616. Ogni
apertura W o S conserva inoltre 130.566.998.016 termini `t*M`; due PCS
richiedono 261.133.996.032 termini per risposta, in contrasto col contratto
che esclude lavoro `qN/t*M`.

Lo sharding letterale non è una correzione: per portare S sotto arena
servono 1.024 shard diadici e i soli 456 row opening iniziali costano circa
956 MB con width 256. Un aggregatore che eviti questi opening, MMCS/DFT
streaming e batch lineare/range tiled costituiscono una nuova PCS e nuovi
kernel, assenti dal repository. La candidata D36 è quindi **respinta nel
backend e contratto correnti**, senza pretendere un lower bound contro ogni
PCS possibile.

Il legame agli originali resta un risultato condizionale distinto: range
restituisce gli stessi `Auth/Key`, il rebasing modifica soltanto offset
pubblici, `linear::bind` fissa forme e target prima di lambda e
`prove_product` termina nel valore autenticato della PCS. `OpeningMac`
copre il seam sotto binding PCS e indipendenza di Delta. Mancano ancora il
teorema binding/HVZK D36 multi-esposizione e la composizione ROM; il test
piccolo prova identità e framing, non questi obblighi o lo schedule fisico.
