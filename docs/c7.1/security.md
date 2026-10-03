# C7.1 — sicurezza

[Design](design.md) · [Specifiche](specs.md) · [Test locali](local-tests.md) ·
[Test su RunPod](runpod-tests.md) · [Archivio](../c7.1-history/README.md)

## Ambito e ipotesi

I §§1–6 definiscono e dimostrano la composizione matematica
`C71B12-Gemma-FixedRun-v1` sul bootstrap B11/B12 originario. Il percorso
efficiente Seed6 conserva la relazione di inferenza, ma richiede il
trasferimento di sicurezza descritto nell'ultima sezione. La correttezza
di test finiti e la corrispondenza generale del programma al protocollo
sono risultati distinti.

Il teorema richiede almeno 78 bit per ciascun vantaggio completo.
Si lavora nel modello dell'oracolo casuale classico, con lavoro e memoria
dell'avversario `T_A=M_A=2^80`, inclusi ambiente, preprocessing e advice,
e `Q_A=2^64` query globali, inclusi candidati Fiat–Shamir scartati.
Le riduzioni restano sotto `T_R=2^121`, `M_R=2^93`, `Q*=2^74`.
A queste risorse si assumono vantaggio AES-256 PRP a quattro blocchi
≤2^-128 e vantaggio DDH P-521 ≤2^-193. Sono ipotesi concrete dichiarate,
non garanzie dedotte dai nomi delle primitive o dai loro test.
Non si assume un setup onesto aggiuntivo.

La riduzione PCS usa distanza del codice e accordo multiplo con
`3*tau<d`, decodifica entro il raggio di unicità, Merkle salato e
preimmagini differite, blocchi di monete Fiat–Shamir e chiusura scalare
nel MAC originale. Non assume una congettura di decodifica a lista.
I parametri sono in [specs](specs.md#pcs-e-ricostruzione-dei-valori).
Le derivazioni componenti riutilizzate sono:

| Risultato | Derivazione, applicata con i parametri correnti |
|---|---|
| Bootstrap reale → ideale e seal | [AES a capacità finita](../c7.1-history/c7.1-gemma31b-design.md#b11-selezione-intermedia-aes-a-capacità-finita), [risorse e seal](../c7.1-history/c7.1-gemma31b-design.md#b12-risorse-lifetime-e-vincolo-same-w), [setup unico](../c7.1-history/c7.1-gemma31b-design.md#b12-capacità-aes-iniziale-per-il-run-continuo); S=1 e M93 |
| Unicità del messaggio PCS | [RS/Merkle e chiusura privata](../c7.1-history/c7.1-gemma31b-design.md#b12-pcs-unicità-del-messaggio-e-compilazione-privata) |
| Privacy delle aperture su endpoint condivisi | [Traslazione congiunta](../c7.1-history/c7.1-gemma31b-design.md#b12-zk-del-consumer-claimless-nel-run-continuo), applicata nel §5 |

Questi rimandi identificano derivazioni, non importano i profili intermedi
o le istruzioni operative dell'archivio. Il conto eseguibile completo è
`complete_fixed_run_composition` in
[c7_1_gemma_plan.py](../../scripts/c7_1_gemma_plan.py).

## 1. Enunciato e oggetti fissati

Il protocollo qui definito compone le componenti B12 già analizzate.
Sotto le ipotesi primitive B12, nel ROM classico, contro avversario e
ambiente con lavoro/memoria inclusi preprocessing e advice ≤2^80 e query
RO globali ≤2^64, valgono:

1. **Soundness del run.** Salvo probabilità ≤ε_S, esiste **un solo W
   estratto all'installazione**, in i16 simmetrico, tale che ogni risposta
   accettata e ogni sua coda KV sono l'inferenza intera specificata su W
   e sul precedente stato accettato. L'estrazione è della riduzione;
   il verifier ordinario non riceve W.
2. **ZK del run.** Esiste un simulatore senza W, con gli output consentiti
   dell'ideale e lo stato Delta/chiavi del verifier corrotto nel gioco
   bootstrap ideale, la cui vista dista da quella reale al più ε_Z.
   Sono inclusi installazione, richieste adattive, query RO e ogni prefisso
   fino alla terminazione, anche se nessuna risposta viene accettata.

I bound razionali sono quelli di `complete_fixed_run_composition` nel
[diagnostico](../../scripts/c7_1_gemma_plan.py): **82,93261 bit soundness e
91,02272 bit ZK**, entrambi oltre 78. Sono teoremi condizionali alle
ipotesi AES-256/P-521 già dichiarate a T121/M93; non sono concrete
dimostrazioni di sicurezza di AES/DDH. Non si aggiunge un setup onesto.

Il profilo selezionato ha un'installazione W/D35, un setup AES iniziale,
un key epoch, tre tentativi totali, 100 token di prompt e 50 generati per
tentativo, O=0/150/300. Errore, abort o esaurimento termina il run.
L'ideale restituisce i token della semantica deterministica selezionata,
oppure un solo esito `Stop` se la preparazione privata non può completarla.
Non espone layer, celle, valori intermedi, ragione privata o progresso
della preparazione. Le lunghezze e l'ordine dei messaggi di prova sono
pubblici; tempi fisici, accessi memoria e side channel non sono il transcript
matematico qui simulato. Lo schedule fisico resta da ammettere.

La tesi ZK parte da una **nuova installazione onesta** del modello privato,
che il simulatore può simulare. Non equivoca una root arbitraria fissata
esternamente prima del gioco. La soundness accetta un modello privato
installato dal prover: non ne attesta la provenienza da un checkpoint.

Il parametro pubblico Γ contiene, in forma canonica e senza campi scelti
dalla prova:

- DAG/metadata/layout pinned, i 772 tensori fisici e l'alias embedding/head;
- esponenti e ricette di `Recipes::compile`, epsilon RMS positivo, scalari
  BF16 esatti, RNE con overflow reject, argmax a parità risolta sull'ID minimo;
- tabelle certificate GELU/softcap, Q30 alle posizioni assolute ammesse e
  `C71-SOFTMAX-EXP30-v1`, con e_Pi=-14;
- i profili PCS flat D35/D34, alphabet/range/padding, capacità iniziale,
  ordine di verifica definito sotto e limiti pubblici dei kernel.

Si prepara e valida Γ **prima di W, bootstrap e prova**. Le tabelle sono
quelle attese dal verifier, derivate dalle ricette certificate; confrontare
un digest fornito dal prover non certifica una tabella. Il teorema è
parametrico in Γ valido; scegliere/calibrare Γ del checkpoint reale non
è una premessa crittografica nascosta. Lettura, controllo delle dimensioni,
compilazione e hashing del parametro sono contati nel §6; la ricerca di
una calibrazione è fuori dal protocollo. Descrittori interni sono quelli
ricompilati dal verifier, non oggetti `Sources` o `Recipes` importati dal
certificato. Nei confronti di stato si conservano le identità complete;
i digest sono nomi nel transcript, non una fonte di autorità separata.

## 2. Preparatore e macchina di accettazione

**Preparatore onesto.** `Prepare(W, Γ, accepted_private_KV, prompt)` esegue
la semantica intera nell'ordine causale, genera i 50 token e completa K/V
del token finale, senza emetterne un cinquantunesimo. Materializza W e A
nel layout flat dichiarato, tutti i raw, byte biased e istogrammi richiesti.
Il suo input non contiene Delta, tag, correlazioni, seed PCS o sampler FS.
Il risultato è uno snapshot immutabile; nessun getter della prova può
ricomputare un'altra quantizzazione o leggere correlazioni non consumate.
Se fallisce, emette soltanto `Stop` prima della root A e di ogni messaggio
di prova. L'algoritmo astratto ammette la materializzazione densa; questo
non la rende compatibile con la memoria hardware obiettivo.

Le valutazioni dopo una sfida leggono esclusivamente questi snapshot e
le sfide precedenti. La casualità delle PCS è separata dalle righe MAC.
`Authenticate(v)` prima calcola v, poi consuma la prossima riga del
sottointervallo assegnato; prodotti e shift PCS consumano maschere proprie.
Questa è la definizione del prover composto, non una proprietà assunta
per ogni closure Rust che possa essere passata alle API dei componenti.

**Stato del verifier.** Dopo installazione/setup:

```text
S = (Γ, C_W, session, key_epoch, capacity_seal, cursor, next_slot,
     accepted = [], live = true)
accepted[j] = (j, O_j, C_Aj, canonical_A_layout_j, tokens_j, receipt_j)
```

Solo la procedura seguente può aggiungere un elemento ad `accepted`.
La sessione conserva anche le chiavi e la capacità finita del bootstrap.
Il prover non fornisce una lista di ricevute da importare nel registro.
Una richiesta nuova si riferisce all'ultimo elemento del registro, oppure
al predecessore vuoto iniziale. Non si sceglie un ramo con una ricerca
per digest. Le A vecchie rimangono sorgenti immutabili di code, non nuove
root attivabili. L'ACK non modifica questo registro.

`VerifyResponse(S, prompt, tokens, C_A, certificate)` è il seguente
algoritmo deterministico con la chiave DV e l'oracolo FS pubblico:

1. Se `!live`, non eseguire altro. Altrimenti impostare subito `live=false`:
   qualunque uscita anticipata conserva lo stato terminale. Controllare
   `next_slot=accepted.len()<3`, sessione, epoch, seal, nonce, predecessore,
   C_W immutabile, prompt di 100 token e token pubblici di lunghezza 150
   con quel prefisso; ogni ID è nel vocabolario. Ricompilare le sorgenti
   a O=150*slot da Γ. C_A deve essere fresca, distinta da W e dalle A
   precedenti. Confrontare Γ e profili con quelli conservati.
2. Calcolare `Recipes::required` dai dati pubblici e riservare una volta
   l'intero intervallo contiguo di righe, nella capacità iniziale. Bruciare
   slot/intervallo **prima** di accedere a quelle righe o a messaggi di prova:
   avanzare `cursor` di `3*required` righe base e `next_slot` di uno.
   Nel transcript iniziale di dominio `C71B12-Gemma-FixedRun-v1` inserire
   Γ, C_W, tutte le identità del registro in ordine, C_A, sessione/epoch/seal,
   slot/intervallo/nonce, prompt e tutti i token. Ogni vettore ha lunghezza
   e encoding canonici. I record dei componenti sono poi concatenati in
   questo **unico Fs**, senza ripartire da transcript locali.
3. Eseguire esattamente la schedule del §3. Il certificato è il prodotto
   ordinato delle prove indicate, con cardinalità fissate, non una lista
   di moduli opzionali. Qualunque errore, prova mancante/eccedente, forma
   invalida, chiave mancante o superamento di capacità/draw termina il run.
   Consumare ogni MAC originale restituito nel batch indicato.
4. Eseguire tutte le PCS finali del §3 e consumare esattamente la riserva.
   La chiusura è il successo congiunto di **tutte** le verifiche, non la
   sola ultima PCS. Verificare framing finale ed esaurimento del certificato;
   assorbire un record finale di completamento in Fs. `receipt=Fs.digest()`.
5. Aggiungere atomicamente `(slot,O,C_A,layout,tokens,receipt)` al registro,
   rendere visibili i 50 token come verificati, impostare `live=true` se
   resta uno slot, altrimenti terminare con tre risposte accettate.

Il framing esterno univoco è parte dell'algoritmo matematico. Il codice
implementa codec e wrapper canonici interni; i controlli strutturali
non costituiscono una verifica positiva dell'intero modello. Un errore restituisce al peer
solo `Stop`; i messaggi di errore dettagliati interni non sono wire.
Il [trasporto dell'accettazione](specs.md#dati-autenticati-e-stato) lega il
completamento alla ricevuta e al certificato pendenti: non è un nuovo
meccanismo di autenticazione. Nel runner CPU i due ruoli usano socketpair
create localmente; un trasporto distribuito deve fornire la premessa di
autenticazione, non sostituirla con il solo hash del certificato.
Una perdita del processo termina il run; non si invoca `reopen`.

## 3. Schedule completa e destinazione degli endpoint

Notazione: `s` è il `P0Statement` ricostruito da S; `r`, `a`, `o`, `m`
sono rispettivamente le sorgenti residuali, attenzione, output e softmax
ricompilate; `b` è la stessa `Bytes` finale da 3.471 sorgenti.
`BW`, `BA`, `BOld[j]` sono liste inizialmente vuote di coppie (forma,key).

Un risultato `(forms,bias,originals)` viene aggiunto come
`(forms[i], originals[i]+Delta*bias[i])`. Il prover usa lo stesso valore
originale più il bias, mantenendo il tag. Non si autentica nuovamente il
valore. Una forma pubblica `(form,bias)` usa `Key(Delta*bias)` e,
nel prover onesto, `Auth(bias,0)`. Le liste non provengono dal certificato.

L'ordine completo è il seguente; le chiamate sono le funzioni matematiche
realizzate dai kernel collegati, con i loro controlli/gradi attuali:

| Ordine | Verifica / compilazione | Destinazione obbligatoria |
|---|---|---|
| 1 | `b.affine_zero_form(plan,s,recipes.affine)`, `b.argmax_zero_form`, `a.mask_zero_form`, `m.zero_form` | Quattro target pubblici in BA; argmax usa `tokens[100:150]` e la Y softcap originale |
| 2 | [`plan.verify_p0`](../../rust/volta-pcs/src/c71_matrix/gemma/caller.rs) su 773 coorti; include il batch prodotti | `weight_forms/weights` in BW; `b.forms(plan,p0)` con cuts e inputs originali in BA |
| 3 | [`rms.verify_rms`](../../rust/volta-pcs/src/c71_matrix/gemma/rms/caller.rs) con le 421 ricette comuni | `rms_forms(pending)` in BA: S, entrambe le X originali per statistica e byte P/S/Y congiunti |
| 4 | `recipes.original_rne(plan,r,p0,norms)`, poi [`rne::verify`](../../rust/volta-pcs/src/c71_matrix/rne.rs) per ciascuna delle 410 richieste nell'ordine del compilatore | Passare **la key e il punto originali** della richiesta come target; aggiungere il MAC byte restituito con `source_rne_form(request.source,point)` in BA |
| 5 | `pairs=recipes.table_pairs(plan)`; [`b.verify_table_rne`](../../rust/volta-pcs/src/c71_matrix/gemma/bytes/quantize.rs) sulle 482 coppie | `table_rne_forms(plan,pairs,pending)` in BA, output e raw originali |
| 6 | [`gelu.verify_lookup`](../../rust/volta-pcs/src/c71_matrix/gemma/gelu.rs), tabelle attese | `gelu.forms(point)` e le tre `originals` X/Y/M in BA |
| 7 | [`gate_up::verify`](../../rust/volta-pcs/src/c71_matrix/gemma/gate_up.rs) sullo statement canonico unico | `gate_up.forms(raw_point,input_point)` e i tre originali R/G/U in BA |
| 8 | [`rope::verify`](../../rust/volta-pcs/src/c71_matrix/rope.rs) sullo statement delle 120 route Q30 | `rope.forms(raw_point,input_point)` e i due originali R/Y in BA |
| 9 | Per layer 0..59: [`attention::verify_qk`, `verify_pv`](../../rust/volta-pcs/src/c71_matrix/attention.rs) sullo stesso statement canonico; PV include il link del contratto M alla Pi originale | `a.qk_routes` e `a.pv_routes`: raw/Q e raw/Pi in BA; conservare in ordine K,V nelle 120 richieste KV |
| 10 | [`kv::verify`](../../rust/volta-pcs/src/c71_matrix/gemma/bytes/kv.rs) sulle richieste del passo 9 | Segmenti presi da `S.accepted`, poi C_A corrente. Un target per vecchia A in BOld, target corrente derivato in BA |
| 11 | [`o.verify_lookup`](../../rust/volta-pcs/src/c71_matrix/gemma/output.rs), softcap atteso | `o.forms` e X/Y/M originali in BA; head RNE era già nel passo 5 |
| 12 | [`m.verify`](../../rust/volta-pcs/src/c71_matrix/gemma/softmax.rs), EXP30 atteso | `m.forms`: massimo, X/Y/M lookup, byte E/Z/Pi del rapporto in BA |
| 13 | [`range::verify`](../../rust/volta-pcs/src/c71_matrix/range.rs) per W flat D35/symmetric(32767), poi A corrente flat D34/Byte | Due forme/target originali range e padding per ciascuna, in BW e BA rispettivamente |
| 14 | [`linear::verify`](../../rust/volta-pcs/src/c71_matrix/linear.rs) su BW/C_W, poi BOld/C_Aj in ordine crescente j, infine BA/C_A | Un'unica PCS per ciascuna sorgente; tutte con righe fresche del tentativo corrente; nessun target rimane aperto |

Per argmax si usa `o.output/o.slack`, 50 righe e vocabolario pinned; la
forma è compilata sui byte originali come nel caso output nativo. Le
ricette delle richieste RNE sono quelle comuni, non shift del certificato.
Nomi `rms`, `gelu`, `gate_up`, `rope` denotano gli oggetti annidati nella
stessa sorgente finale, non copie con layout precedenti all'estensione.

Il conteggio è **775 target W**, **4.446 target A corrente**, **uno per
ciascuna vecchia A**. BA si riconcilia con la tabella del
[compilatore](../c7.1-history/c7.1-gemma31b-design.md#b12-profilo-numerico-comune-ricette-derivate-dai-produttori):
1545+1264+410+964+3+3+2+240+1+3+5+4+2=4446. BW ha
773+2=775. I range precedenti si ereditano esclusivamente dal registro;
le aperture precedenti non ereditano tag o righe. W ha tre aperture,
A0/A1/A2 hanno 3/2/1 aperture. Non compare una PCS per token o una nuova
sorgente separata per tracce, bit, probabilità, logits o KV.

## 4. Soundness: dalle aperture alla transizione accettata

**Evento globale.** Riutilizzare l'unico esperimento di cattivi prefissi
B12, con Q*=2^74 globale, i bad event Merkle (collisione e preimage
differito), bootstrap/seal, PCS/RS, range, MAC e tutti i blocchi GKR/RNE/
lookup/forme già sommati in `ordinary_KV_output_and_EXP30_composition`.
La nuova schedule non altera quei polinomi o aggiunge sfide; fissa i loro
prefissi in un unico transcript. Query a candidati scartati e prefissi
prima di una pubblicazione rimangono inclusi. I digest di profilo/stato
sono nel medesimo oracolo/query census; le identità attese non si leggono
da una prova. Non si assume indipendenza dopo aver condizionato sul futuro
successo né si moltiplica di nuovo Q* per tre tentativi.

La riduzione costruisce la mappa Merkle alla prima dichiarazione di C_W
con le sole informazioni al suo prefisso, usando il decoder unique-radius
B12 una volta. Ripete per ciascuna A effettivamente dichiarata, al più tre.
Queste mappe non vengono ricalcolate dopo le sfide o scegliendo un futuro
predecessore. Sulle root prive di messaggio vicino si usa la convenzione
del lemma PCS: un'accettazione utile richiede il relativo bad event.
Fuori dall'unione degli eventi, tutte le aperture accettate sono forme
dei medesimi quattro messaggi; il range rende W i16 simmetrico e A byte,
con il suffisso flat nullo. Nei rettangoli, il padding interno prescritto
è controllato dai rispettivi produttori/forme, non dal solo suffisso flat.

**Lemma di cucitura dei valori.** A quel punto il MAC di un input P0,
il MAC dello stesso output passato alla RNE e il target byte della PCS
denotano un unico valore. La verifica RNE non termina con una nuova
autenticazione libera: la forma dei byte raw è l'originale restituito.
Per ogni altra famiglia vale la stessa identità del §3. In particolare:

- una coorte matrice falsa ha una discrepanza nonzero su C/X/W fissati;
  le sonde e la riduzione P0 già contate la escludono; i 773 endpoint
  W proiettano sempre i 772 tensori fisici della W installata;
- RMS collega P=XW, S=sum X² e Y; le X locali V e gli alias globali
  pre-norm K/V conservano l'ID originale. Non basta dimostrare S/Y fra loro;
- le 410 richieste RNE originali e le 482 sonde sono disgiunte e coprono
  i 892 produttori RNE; RMS/GELU/EXP30/softcap completano tutti i 1.434
  owner di attivazioni. L'ulteriore lookup embedding appartiene a W;
- QK/PV usano quotient-GQA e gli eager rectangle dichiarati; Pi è la stessa
  sorgente in maschera causale, EXP30 e PV. Il MAC M di PV è scaricato
  verso Pi, non conservato come testimone libero;
- massimo/differenza/lookup EXP30/somma/rapporto esatto determinano ogni
  Pi ammessa; le posizioni future e padded sono nulle. Tutti gli ausiliari
  appartengono alla stessa A; gli istogrammi precedono alpha;
- somme, scale, head, softcap e argmax chiudono sui loro byte originali.
  Tutti i valori semantici sono nel range del loro produttore, senza
  trasformare byte-validity in una prova di RNE o di i16 simmetrico.

Il passaggio dal campo agli interi usa gli envelope già provati: prodotti
i16, accumuli P0, QK/PV e RoPE hanno differenze assolute <p; l'affine ha
`|R-aX-bY|≤2^47+2^46<p`. Le routine RNE/RMS/ratio verificano i predicati
interi con i byte originali, u128 e profili pubblici limitati. Per EXP30
`2^30≤Z≤450*2^30<2^39`. Non si accetta un'identità soltanto modulo p
come identità intera fuori da questi inviluppi.

**Induzione su layer, token e risposte.** Nel primo tentativo lo storico
è vuoto. Fissato W, embedding identifica il valore iniziale per ogni token
pubblico; le identità appena provate determinano i successori nell'ordine
del DAG. A una query t la maschera limita K/V a posizioni ≤O+t. All'interno
di un layer K/V di quelle posizioni sono calcolati da layer precedenti:
non c'è un ciclo attraverso il token futuro. L'head usa righe 99..148 e
argmax le collega esattamente a token 100..149. Induzione su queste 50
decisioni dà i token della generazione sequenziale, anche se il certificato
li presenta insieme. Le sorgenti di 150 righe certificano anche K/V
del token 149: la promozione non lascia l'ultimo token pendente.

Supporre ora vere le prime j risposte accettate. Al passo j il registro
fornisce proprio quelle A e i loro layout, mai una ricevuta importata.
Il router KV dimostra, per ciascun endpoint originale, la forma

```text
L(KV)[r] = sum_{i=0..j} sum_{t=0..149,c}
            eq(r_key,150*i+t) * eq(r_channel,c) * tail(A_i)[t,c].
```

I blocchi sono allineati nei domini locale e globale. Ogni vecchia PCS
lega l'aggregato fresco alla stessa A_i già decodificata; il target
corrente è la differenza dall'aggregato degli **originali** QK/PV.
Il lemma di batching già contato esclude una compensazione falsa fra
endpoint. La cucitura quindi usa esattamente il KV prodotto in precedenza
con W, più la coda corrente. L'induzione DAG dà la risposta j e la sua
coda sul medesimo W. Solo adesso il passo 5 promuove A_j.

Un errore a qualsiasi altezza lascia invariato il registro e termina.
Replay, fork, ACK, certificati parziali e una sola PCS valida non possono
creare un'ipotesi induttiva. Perciò il primo falso stato accettato implica
uno degli eventi già limitati: **Pr[false acceptance]≤ε_S**, senza un
termine aggiuntivo per un'induzione deterministica o una promessa di
«integrazione corretta».

## 5. Simulatore congiunto e NoPeek

Sostituire il bootstrap reale con il funzionale B11 con la perdita
ε_boot già contata. Il simulatore esegue V* una volta, senza rewind,
conservando le sue query e il suo stato. Installa una W fittizia unica
di 772 tensori zero con il prover PCS ordinario. Su una richiesta ottiene
dal funzionale dell'inferenza gli output pubblici o `Stop`; in quest'ultimo
caso termina alla stessa boundary prima della prova. Non cerca W.

Per ogni risposta completa prepara lo snapshot fittizio del
[lemma zero-W](../c7.1-history/c7.1-gemma31b-design.md#b12-output-canonico-lm_head-softcap-e-decisioni-nella-stessa-a):
hidden/raw/KV zero, D=0 ed E=2^30 su tutte le celle lookup, comprese
quelle vietate; su ogni query viva Z=k*2^30 e Pi=RNE(2^14/k),
k=O+t+1. Z è zero sulle query padded; Pi è zero sulle posizioni
vietate/padded. Le maschere nella somma Z escludono gli E vietati.
Istogrammi, differenze e byte biased sono quelli veri di questo snapshot;
A fittizia **non è il vettore zero**. Qualunque profilo valido della
famiglia ammette tale trace: RMS ha epsilon positivo, GELU/softcap(0)=0,
RNE(0)=0 e Pi entra nel range simmetrico fino a k=450.

Il simulatore esegue i prover ordinari nell'ordine del §3 usando le righe
ideali ricostruite dalle chiavi corrotte e valori uniformi. Per il solo
target pubblico argmax, con valore effettivo F sullo snapshot fittizio
e bias/target pubblico b, usa `Auth(F,Delta*(b-F))`: la key del verifier
rimane `Delta*b`. Con slack unsigned zero F=0, anche se il token ideale
non è quello scelto dal modello zero. È un'operazione del simulatore DV,
non del prover reale. Non corregge il target del verifier, non cambia
la root fra operatori e non programma FS.

**Disciplina NoPeek scaricata.** L'algoritmo del §2 ha quattro classi di
plaintext autenticati:

| Classe | Dati letti prima della prossima riga |
|---|---|
| Probe, endpoint e aggregati KV | Snapshot W/A immutabili, forme e sfide già nel transcript |
| Coefficienti sumcheck/GKR, funzioni byte e split | Tabelle/celle deterministiche di quegli snapshot e sfide precedenti; dimensioni/alias pubblici |
| Istogrammi e prodotti intermedi | Snapshot e operandi già fissati; istogrammi prima di alpha, prodotti prima della propria mask |
| Chiusura PCS | Coin PCS separati, target originale, replay pubblico; shift MAC proprio e monouso |

La lista è esaustiva dei kernel della schedule. Nessuna classe legge una
correlazione ancora inutilizzata per decidere il proprio valore, shape,
alias o ramo. I lookup respingono i poli dell'**intera tabella pubblica**;
su un witness onesto questo include ogni possibile polo privato. RMS,
overflow e istogrammi sono preparati prima di A; i successivi controlli
su dati privati sono equazioni MAC, non emissioni diagnostiche. Un input
pubblico malformato, un polo pubblico, un sampler o un arresto scelto da
V* sono predicati della vista; i fallimenti dei sampler privati stanno
negli eventi statistici già contati.

**Una sola traslazione della vista.** Passare ai coin uniformi e alle
label Merkle ideali come nella prova claimless B12. Fissare una vista
pubblica completa, inclusi tutti i prefissi FS e la casualità di V*.
Per ognuna delle quattro sorgenti si usa un unico inverso destro canonico
del sistema RS sull'**unione** dei punti esposti nell'intero run. W/A0
hanno ≤1536 punti, A1 ≤1024, A2 ≤512, coperti dai 1536 pad. Le differenze
fra snapshot reali e fittizi determinano così una sola traslazione dei
pad iniziali per sorgente, non una sostituzione indipendente a ogni proof.

Per un MAC con key fissata `k=m+Delta*x`, la correzione d=v-u si conserva
ponendo `du=dv` e `dm=-Delta*du`. NoPeek rende queste traslazioni
triangolari nell'ordine di consumo. Gli alias condivisi hanno **un'unica
dv**. Le operazioni lineari, i tag dei residui veri e il batch QuickSilver
si conservano mediante la propria maschera fresca, con i segni nativi.
Per i target pubblici si conserva k e si trasla il tag come sopra.

Ogni PCS conserva coefficienti visibili, OOD e righe con le traslazioni
di rango pieno della prova B12. Al terminale, per il suo scalare z,
covettore `A*z+B`, blind g e shift eta:

```text
dg = -gamma*dh,       deta = gamma*A*dz.
```

Una key condivisa da due componenti usa la stessa dz; ogni PCS ha il
proprio eta e può applicare la formula. Un aggregato KV di una vecchia
A usa il valore di quella medesima A, con una riga MAC nuova. Non è
necessaria indipendenza dei witness W/A o degli endpoint. Le coordinate
casuali delle diverse PCS e i 39 stream sono disgiunti; quelle iniziali
di una stessa sorgente sono invece traslate una sola volta.

Questa mappa ha inversa cambiando segno alle differenze degli snapshot
e applicando le stesse equazioni nell'ordine inverso. Conserva tutta la
vista, incluse correzioni, tag, salti, aperture, roots, record finali e
quindi ricevute. I challenge sono quelli dei **veri prefissi FS**; non
si assume che siano uniformi dopo aver fissato la vista. La sola
eccezione al passo OOD resta rho=0, già addebitata come Q*/q. Nessuna
divisione per Delta, gamma o il coefficiente A viene aggiunta.

La scelta adattiva della richiesta successiva è una funzione della vista
preservata. Le due esecuzioni scelgono quindi lo stesso prompt, lo stesso
predecessore e lo stesso punto di terminazione; per l'induzione sulle
tre risposte gli snapshot fittizi mantengono W=0 e le proprie code zero.
La proiezione su un prefisso interrotto conserva l'uguaglianza di legge.
Ritornando da label/coin ideali alla PCS ordinaria fittizia si ottiene

```text
ε_Z = ε_boot + 2 ε_joint_Merkle_hiding_and_coins
             + Q*/q + 2 ε_joint_private_sampler.
```

È la stessa foresta congiunta da 526 alberi, 39 stream e sei aperture A
già contata. Non si sommano nuove ZK per ogni operatore, non si azzera
l'hiding delle root e non si deduce ZK dalla sola accettazione del dummy.

## 6. Risorse, riuso formale e confine runtime

`complete_fixed_run_composition` conserva le somme razionali precedenti
e aggiunge al riduttore un envelope esplicito per assemblaggio, stato e
preparazione del dummy: **2^80 operazioni u64, 2^70 parole, 2^42 eventi
RO onesti**. Il massimo totale rimane <T121/M93 e le query <Q*=2^74.
Questo è un upper analitico per entrambi i ruoli, non una misura.

Il preparatore denso valuta al più tre grafi con ≤450 posizioni, 60 layer,
larghezza ≤21504 e vocabolario 262144. Anche l'enumerazione delle matrici
rettangolari e dei raw, con ≤2^12 operazioni u64 per operazione di campo,
resta sotto 2^70; gli snapshot W e tre A richiedono <2^38 parole.
Il costo maggiore, già ereditato, è quello di decoder, PCS e replay
GKR densi. Per la composizione, anche visitare ≤2^19 cubi su ciascun dominio
≤2^35, per nove aperture e con lo stesso fattore 2^12, usa <2^70
operazioni. Lettura/hashing dei parametri pubblici e dei record, dispatch,
registry e propagazione di key/forme stanno sotto l'ulteriore envelope.
I cap pubblici dei compilatori sono applicati prima di quelle allocazioni.
Non si decodifica ogni candidato FS: quattro decoder totali, mentre il
trie/tape delle query candidate rimane nel costo globale già dimostrato.

Le correlazioni sono **11.466.948 righe base** per i tre tentativi,
entro 16.777.206 iniziali. La composizione non aggiunge MAC, PCS, stream,
sfide o termini d'errore: aggiunge confronti pubblici e una regola di
promozione. La preparazione del parametro numerico da cui si sceglie Γ
e la sua qualità come modello sono questioni distinte; leggere le tabelle
di Γ e verificare che siano quelle attese non è costo zero nel protocollo.

| Fatto usato | Evidenza e limite del trasferimento |
|---|---|
| Operazioni lineari preservano MAC originali | [`Mac.Valid.add/smul/sum`, `ofPublic_valid`](../../lean/VoltaZk/Mac.lean); applicati ai segni nativi k=m+Delta*x |
| Correzioni e residui hanno simulazione sui prefissi | [`BlindSumcheck.realView_map_publicView`, `bsc_zeroBatch_perfect_zk`](../../lean/VoltaZk/BlindSumcheck.lean), batch prodotti/range B12 e [G2 §3.1](../c7.1-history/c7.1-committed-mac-opening.md#31-simulatore-ideale-fs-nessuna-programmazione-delloracolo); il §5 scarica shape, NoPeek e alias del caller |
| KV è append dei tail accettati | [`prefix_stability`, `accepted_append_tails_induction`](../../lean/VoltaZk/C7StatefulAlfc.lean); il §4 dimostra la premessa di validità delle code per questa relazione |
| Unione eterogenea con Q globale | [`c7_gemma_gkr_heterogeneous_qfs_union_bound_once`](../../lean/VoltaZk/C7GemmaGKR.lean); i gradi sono quelli B12 ricontati, non il vecchio numeratore congelato |
| Root → stesso messaggio → endpoint | Analisi RS/MCA/Merkle e invariante scalare nativo B12; nessun lemma Lean storico è presentato come dimostrazione del fork PCS |

## Estensione Seed6 e obblighi residui

Il trust model del percorso efficiente include la premessa autorizzata:

```text
Adv_EA-LPN-SL-reg*(675,70778880,353894400,11,Fp;
                  T=2^121,M=2^93,one-leakage) <= 2^-80.
```

Non è un risultato empirico LPN né una conseguenza dell'ipotesi AES.
Seed6 usa Fp6→Fp3, due seed a ruoli opposti, guard dei cammini, cGGM
con oracoli separati per nodo, coin con commitment/apertura e F_EQ.
Le identità implementate e la macchina monouso sono in
[specs](specs.md#correlazioni-seed6); il [conto condizionale](../c7.1-history/construction-screen.md#seed-fp6-compressione-a-95-bit-nel-singolo-setup)
rimane distinto dai bound completi dei §§1–6.

Il guard impone `gamma*(gamma-beta)=0` sui MAC originali prima delle
correzioni cGGM. Con beta nonzero estrae un cammino binario; il ramo beta
zero ha una simulazione separata. Il bound ideale è `(t*h+1)/|Fp3|`.
Il costruttore onesto campiona beta in Fp* senza abort osservabile.
Il cGGM usa `left=H_D(x), right=x-H_D(x)` dopo uno split iniziale
indipendente. La riduzione condizionale contro il receiver paga
`Q_ROM/|Fp3|` per le query anticipate ai nodi nascosti.

F_EQ autentica gli input con due chiavi fissate prima delle correzioni
e apre solo share del prodotto `(Delta0+Delta1)*(wbar-vbar)`.
Una seconda coin precede commitment e aperture ordinate per ruolo.
Con chiavi B11 nonzero, una share malevola fissata prima dell'apertura
accetta un mismatch con probabilità ≤`1/(|Fp3|-1)`; la distanza statistica
fra viste di rifiuto è ≤`1/(|Fp3|-2)`, con abort e burn. Il seed EA
derivato dalle aperture accettate richiede blind onesto fresco, binding
dei commitment e nessun retry. L'analisi locale aggiunge un termine
<2^-108; non costituisce una riduzione globale già conclusa.

Restano da chiudere la composizione malevola di bootstrap/guard/cGGM/
split/F_EQ/EA, il conto completo delle risorse della riduzione, e la
corrispondenza dei codec e dei prefissi nativi all'esperimento matematico.
La sostituzione reale→ideale del §5 riguarda ancora B11/B12.
Canale autenticato e journal durevole non riportabile indietro sono
premesse esterne; i socketpair dei test non le realizzano in distribuito.
Il runner CPU trasporta ora anche Γ/tabelle, installazione e richieste
sui socketpair e ricompila Γ dal lato V. I nuovi record pubblici e i
contatori locali non certificano le tabelle, non autenticano TCP e non
chiudono il raffinamento della composizione Seed6. Le misure di fase sono
diagnostici locali fuori dal transcript; non contengono valori privati.
Nessun bound 82,93/91,02 viene attribuito alla composizione Seed6 completa.

Le credenziali provider locali non fanno parte del protocollo. Il
[preflight dei permessi](../../benchmarks/results/c71-local-secret-permissions-2026-10-03-d14843b3e1fb.json)
rifiuta `.env` non regolare, non posseduto dall'utente o con qualunque bit
di gruppo/altri; non legge né registra i valori. Il file locale rilevato è
ignorato da Git ed è stato portato da `0664` a `0600`.
La deadline di spesa del provider è anch'essa esterna al protocollo.
`runpodctl` v2.12.0 ha rimosso i relativi flag perché il backend li ignorava;
il [runbook](runpod-tests.md#stato-e-sequenza-operativa) impone quindi un
hard stop finché non esiste un limite provider verificabile o un diverso
controllo di spesa autorizzato; il
[record](../../benchmarks/results/c71-runpod-deadline-audit-2026-10-03-5fba934b009f.json)
non attribuisce credito al protocollo.

Il [prover CPU](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_prove.rs)
e il [registro dei due ruoli](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_state.rs)
collegano ora la schedule e la promozione dopo i journal. Per il programma
canonico restano Γ reale validato, verifica positiva dell'intera pipeline,
correttezza dei getter su tutti gli operatori e alias e convalida della
copertura dei MAC originali sui certificati prodotti. La presenza del
codice non scarica questi obblighi. Le ottimizzazioni che conservano messaggi e polinomi devono
preservare anche l'ordine delle letture prima delle correlazioni, detto
NoPeek, e contabilizzare tutte le risorse. La parità ridotta di byte,
transcript e MAC è un controllo necessario, non una prova generale Lean.
Il [controllo locale a due tentativi con Seed6 reale](../../benchmarks/results/c71-real-two-attempts-2026-10-03-262e89febe2c.json)
è scaduto durante il secondo tentativo e non scarica questo obbligo.

Il [collegamento dello scanner iniziale](../c7.1-history/canonical-initial-scan.md)
riordina soltanto l'accumulazione degli stessi coefficienti originali:
non cambia polinomio, posizioni dei pad, sali o messaggi. Lo scanner non
riceve monete PCS né correlazioni; il contratto interno richiede una sola
emissione per coefficiente e valori identici al getter immutabile. La
copertura delle righe canoniche e la partizione fissa delle tessere
supportano questo contratto; il solo contatore di emissioni nel coset
non prova l'unicità degli indici di uno scanner arbitrario. Root e aperture
sono confrontati col commitment denso indipendente a monete fissate su
dominio piccolo. Non è una prova per tutti i produttori canonici, del
raffinamento CUDA o della composizione Seed6; non cambia i bound dichiarati.

Lo stesso contratto immutabile vale per il
[lettore a finestre delle query](../c7.1-history/canonical-query-windows.md).
Il reader emette solo byte originali; il codice PCS conserva padding
esterno, posizioni dei pad privati e ordine dei resti. Nessuna finestra
diventa un nuovo commitment o una nuova autenticazione. Il callback
non riceve coin PCS o correlazioni. Il confronto ridotto della catena
controlla transcript, codec, S1 trattenuto e chiusura sugli stessi MAC;
un reader alterato è rifiutato dal root già fissato. Questi controlli
non attestano la composizione canonica o un nuovo lemma generale.

Le [riduzioni S1 sourcewise](../c7.1-history/canonical-residual-scan.md)
spostano soltanto somme e prodotti lineari: il peso Eq usa esclusivamente
il prefisso già fissato e l'indice originale. I contributi duplicati a
un indice folded sono sommati, non reinterpretati come nuove sorgenti.
Singleton, ogni coset, OOD e retention rimangono passaggi separati.
Gli errori del produttore/consumer si propagano prima di installare S1;
il contratto di unicità dei byte originali resta quello dello scanner,
non è dimostrato dal solo conteggio. Il controllo ridotto rende il getter
originale inutilizzabile e confronta l'intera prova col percorso denso,
ma non scarica il raffinamento dei produttori canonici, CUDA o Seed6.

Il [collegamento degli stadi PCS](../c7.1-history/canonical-pcs-stages.md)
conserva polinomi, sali, codec e sfide. La cache di Q dipende dalle basi
Pow già fissate: le due sfide cambiano solo le ampiezze del numeratore.
La cache termina al secondo fold e non riusa monete o correlazioni.
La selezione di coset è una scelta fisica, non una nuova garanzia ZK o
di memoria. Ammettere D35 nel riferimento CPU non prova l'esecuzione
canonica, il limite temporale o la composizione Seed6.

Il [gather range](../c7.1-history/canonical-range-gather.md) permuta solo
indirizzi pubblici: prima coordinata MSB e bit del sottoalbero preservati.
Il reader non riceve sfide, MAC o correlazioni e riusa gli stessi owner
immutabili di checkpoint, istogrammi e byte biased. Le intersezioni delle
tessere non dipendono da sfide future. I test controllano la bijezione
finita e il confronto con gli originali. Il
[consumer range A](../c7.1-history/canonical-windowed-range.md) collega ora
quel reader alla prova CPU, riusando l'autenticazione e l'ordine FS della
fraction tree. La matrice privata H contrae i prodotti dei quattro figli
solo sul tail pubblico; i fold di entrambe le coordinate di H usano le
sfide già emesse. Non sostituisce gli endpoint originali con nuovi MAC.
La sua identità algebrica e la parità ridotta non sono un lemma Lean
generale o una validazione D34/CUDA/Seed6. L'istogramma privato è raccolto
nel commitment originale, prima delle correlazioni, e autenticato con le
righe fresche del range. Errori di scan/callback non producono una prova
alternativa e restano terminali per il runner.

Il range W riusa questa stessa fraction tree su parole signed originali;
il gather riordina indirizzi, non valori o bias. L'istogramma privato è
calcolato dal packed immutabile all'installazione, prima delle correlazioni,
e riautenticato a ogni prova. Il suffisso zero appartiene allo stesso dominio
del commitment. Il collegamento non aggiunge un lemma Lean né scarica gli
obblighi aperti di raffinamento, composizione Seed6 o implementazione CUDA.
I nuovi kernel range condividono la rappresentazione Fp3, ma il controllo
host e il binario compilato non provano la loro esecuzione concorrente.
L'owner nativo rifiuta alias nei fold H/canopy, handle ritirati o di un
altro contesto e input parziali; scarica solo output piccoli dopo fencing
e controllo canonico. Il test con driver differito verifica anche che un
errore asincrono non pubblichi output e che il contesto resti fermato.
Il collegamento Rust usa ora quel fencing nei callback del prover range
comune, prima dell'autenticazione e delle successive sfide FS. I test
attraversano l'ABI con driver host differito e chiudono i target sugli
stessi MAC originali; includono errori di reader, launch, fence, output e
cleanup, senza continuazione CPU. La libreria è codice locale fidato,
non un input fornito dal certificato. I kernel non vedono transcript o
correlazioni. Questi controlli non provano la concorrenza CUDA, la correttezza
delle riduzioni CAS reali o l'esecuzione GPU: restano obblighi da verificare.

Il kernel denso i16 conserva la somma di prodotti interi mediante split
signed a due byte, quattro prodotti INT8 e correzioni affini esatte;
il cap K limita tutti i prefissi degli accumulatori int32. Non introduce
cast float, saturazione, nuovi MAC o un RNE diverso. Il modello host
verifica split, frammenti, somme lane e padding contro dot product i128.
Non prova l'esecuzione PTX o lo schedule concorrente. L'owner ora rifiuta
W parziale/riscritto e non pubblica handle inizializzati per prodotto/RNE
finché il flag non è valido dopo fence. Gli errori sono terminali nello
stesso contesto del range. Il RNE separato mantiene signed-48 e ±32767;
la parità host usa una divisione i128 indipendente e il riferimento Rust.
Il binding del packed residente al W impegnato e il lifecycle terminale
del preparatore completo restano da collegare nel runner; il puntatore W
privato dell'owner non dimostra da solo tale identità. Nessun output del
componente da solo costituisce una prova accettabile.
Il raffinamento di questa implementazione al prodotto intero del §4 non
è un nuovo lemma Lean acquisito.

I lemmi Lean in §6 giustificano le specifiche identità indicate. Non
dimostrano il fork PCS, il wrapper Rust, CUDA o il raffinamento completo
Gemma. Tempi e accessi fisici restano fuori dalla vista ZK matematica.
La fattibilità a memoria e tempo limitati è verificata separatamente
secondo [runpod-tests](runpod-tests.md).
