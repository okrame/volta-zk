# C7.1 — PCS e stato persistente: candidata, non ammissione

2026-09-11. [Stato](status.md) · [Design](design.md) · [Evidenza](evidence.md).

## Risultato e criterio del proprietario

La variante studiata combina PCS con parametri ridotti, RNE in gruppi senza
padding aggiunto e KV cumulativo nel nuovo snapshot. Il solo KV cumulativo
non risolve il lifetime di W: il commitment B12 installato ha tre esposizioni.
Le prime due costruzioni restano **non selezionate**:

| O | B12 attuale, upper | KV cumulativo, W a tre esposizioni | KV e W entrambi collegati al predecessore |
|---:|---:|---:|---:|
| 0 | 65.053.244 | 27.408.344 | 26.686.168 |
| 150 | 78.945.726 | 34.669.384 | 41.157.548 |
| 300 | 92.723.304 | 34.669.384 | 41.157.548 |
| PCS per risposta | 2 / 3 / 4 | 2 / 3 / 3 | 2 / 4 / 4 |

Sono **upper condizionali del wire della risposta**, con corpo, RNE, range,
maschere, sali, frontiere Merkle massime, header, frame e chiusura. Non sono
certificati Gemma validi misurati. I lower corrispondenti della seconda
variante sono 17.857.848 / 26.835.276 / 26.835.276 byte e conservano le
omissioni del lower B12: GKR congiunti e hash fratelli. Il lower non è un
obiettivo raggiunto. Bootstrap/offline e setup restano voci separate da
misurare e contare una volta nel confronto della conversazione completa.

La seconda variante evita anche il budget di maschere W lineare nel numero
di tentativi pianificati, ma paga una PCS W aggiuntiva dopo il primo turno.
Non è dimostrato un minimo globale: lo screen visita soltanto 60 geometrie.
Il minimo wire della famiglia usa 448 query; il componente nativo studiato
ne usa 456. Il margine di questo screen PCS non sostituisce il bound completo.

Una terza candidata, [stato unico W/A/KV](#stato-unico-wakv-con-installazione-separata),
proietta **26.653.252 / 28.444.684 / 28.444.684 byte** completi, pagando
anche il collegamento al W installato prima del primo prompt. Usa due PCS
per risposta e riduce i termini delle query nei tre prefissi confrontati.
Il dominio D36 aggiunge però padding e lavoro nei sumcheck iniziali.
È la pista da verificare per il vincolo congiunto byte/lavoro; non è ammessa.

**L'obiettivo del proprietario resta aperto:** manca la verifica di lavoro
totale non crescente e la composizione di sicurezza della candidata. Non
si deduce quella verifica dalla riduzione di byte, correlazioni o FFT.

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
| 0 | 34,32,30,29,25,24 | 214.116 |
| 150/300 | 34,32,31,28,27,26,25,24 | 280.208 |

Il sovrapprezzo rispetto ai due gruppi è 133.240 / 199.332 byte, incluso
nella tabella iniziale. Il numero di foglie e nodi dei 256-entry alberi
rimane quello separato; resta da addebitare il sumcheck iniziale aggiunto,
le forme, il routing e lo schedule. La sola uguaglianza del numero di
foglie non dimostra lavoro totale uguale. Il kernel condiviso resta test-only.

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

La memoria persistente fuori H100 autorizzata dal proprietario permette
di studiare la conservazione dei dati iniziali di commit fino all'ultimo
consumer. Non permette di saltare copie, trasferimenti, nuovi pad, proof
fresche o il costo di creare quella cache. Il prover C71 corrente continua
a rimaterializzare: la nuova API di lettura dei dati conservati, descritta
sotto, è verificata come componente e non ancora collegata al suo wrapper.
Rimangono invariati H100, arena, trust model e assenza di autorizzazione
a run pesanti/provider. I dati canonici non vengono materializzati localmente.

Prima della selezione servono quindi contabilità completa con disuguaglianza
contro la baseline, composizione ROM/ZK/risorse, routing canonico e prova
completa valida. I lemmi `Mac.Valid.add/smul/sum` e l'induzione KV già
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
Il positivo piccolo aggiunge W a una esposizione e D13 con primo fold 5;
non è un'esecuzione del nuovo protocollo di stato.

Il conto completo sostituisce le quattro PCS mobili con le due S,
mantenendo prudenzialmente i loro frame e la riserva metadata di 128 byte.
Al primo turno aggiunge la PCS di installazione e 36 byte per il link.
I gruppi RNE senza padding aggiunto e tutti gli altri consumer restano
nel conto. Ne risultano gli upper 26,65/28,44/28,44 MB; non si eliminano
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
includere questi covettori, il sumcheck RNE aggiunto, le forme di link,
il KV e lo schedule fisico della cache. Rimane `full_work_nonincrease_verified:false`.
