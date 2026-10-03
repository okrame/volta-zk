# C7.1 — specifiche

[Design](design.md) · [Sicurezza](security.md) · [Test locali](local-tests.md) ·
[Test su RunPod](runpod-tests.md) · [Archivio](../c7.1-history/README.md)

## Input e identità

Il checkpoint testuale è `google/gemma-4-31B` alla revisione
`5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89`.
I [metadati](../../manifests/c7-d126-gemma31b-source-metadata-v1.json)
hanno SHA-256 `1ddce0cc399d636488728f663fb756804a07e6b3ad14d43f527c7ad746e27ce2`.
Il [manifest dei terminali](../../manifests/c7-d126-gemma31b-terminals-v1.csv)
fissa 772 tensori privati, 60 scalari pubblici e gli alias. Embedding e
head condividono lo stesso tensore fisico W e lo stesso esponente.
Il [workload](../../manifests/c7-d126-gemma31b-workload-v1.json), SHA-256
`70875c659be2b2bc0079a954233da639fe1584136c17f8fb353b589454a5d62b`,
fissa i prompt dei tre tentativi O=0/150/300. Token speciali e template
concorrono alla lunghezza; il test non aggiunge una tokenizzazione diversa.

| Shard originale | Byte | SHA-256 completo |
|---|---:|---|
| `model-00001-of-00002.safetensors` | 49.784.788.364 | `186fa361e76abbb5f48ffb3d9965181a5da33522e39c25eb75d7241da1637aac` |
| `model-00002-of-00002.safetensors` | 12.761.549.884 | `b78ae8294981a6d674c47f2261d34240b7539bbeafb4f7d0525f6167946e6da0` |

Γ contiene le identità precedenti, una mappa di 772 esponenti W e 1.435
esponenti semantici, le ricette numeriche, le tabelle certificate, i layout,
i parametri PCS e i limiti pubblici. Gli esponenti sono in [-128,128].
Pi ha esponente −14; il lookup embedding eredita quello W. Mancanze,
duplicazioni, elementi extra e alias incoerenti sono rifiutati.

Il verificatore ricompila Γ tramite
[profile.rs](../../rust/volta-pcs/src/c71_matrix/gemma/profile.rs) e
[canonical_state.rs](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_state.rs).
Il digest di sole ricette è distinto dal digest semantico completo, che
include corpi delle tabelle, finestre RoPE, layout, riserve e cap del codec.
Il confronto di un digest ricevuto non certifica i valori delle tabelle.

## Semantica numerica

Un intero x con esponente e denota x·2^e. Gli output i16 ordinari ammessi
sono [-32767,32767]; −32768 è un marcatore di overflow. L'unica eccezione
è `U/global/argmax_slack`, che per contratto rappresenta una distanza u16
come `s-32768` e quindi usa l'intero intervallo i16.
RNE arrotonda al più vicino, scegliendo l'intero pari nei pareggi.
Raw signed-48, statistiche e byte biased conservano i range e l'ordine
del [layout byte](../../rust/volta-pcs/src/c71_matrix/gemma/bytes.rs).
Non si sostituiscono identità intere con uguaglianze modulo il campo
senza il limite aritmetico prescritto in [security](security.md#4-soundness-dalle-aperture-alla-transizione-accettata).

| Operazione | Regola e codice di riferimento |
|---|---|
| Matrici e prodotti pesati | Accumuli interi originali; output RNE con shift `e_Y-e_X-e_W`. [P0](../../rust/volta-pcs/src/c71_matrix/p0.rs), [caller](../../rust/volta-pcs/src/c71_matrix/gemma/caller.rs) |
| RNE | [rne::integer/divide](../../rust/volta-pcs/src/c71_matrix/rne.rs): range raw verificato prima dello shift; shift ≥48 dà zero, shift ≤−15 ammette solo raw zero; nessuna saturazione |
| RMS | [rms::Integer](../../rust/volta-pcs/src/c71_matrix/rms.rs): P=XW, S=ΣX², epsilon=10^-6; confronti esatti delle mezze soglie al quadrato, senza floating point; limiti u128. [Route per testa](../../rust/volta-pcs/src/c71_matrix/gemma/rms.rs) |
| Somme residuali e scale | [affine.rs](../../rust/volta-pcs/src/c71_matrix/gemma/bytes/affine.rs): R=aX+bY, coefficienti dyadic BF16 esatti, modulo dei coefficienti ≤2^30, input i16 e raw signed-48 |
| GELU | `C71-GELU-RNE-v1`: RNE della tanh-GELU con coefficiente 0,044715 e scale originali, tabella pubblica certificata; [lookup](../../rust/volta-pcs/src/c71_matrix/gemma/gelu.rs) |
| RoPE | `C71-RoPE-Q30-v1`: coppie Q30 alle posizioni assolute, geometrie local/global pinned, shift `e_Y-e_X+30`; [rope.rs](../../rust/volta-pcs/src/c71_matrix/rope.rs) |
| QK/PV | GQA con quoziente fra teste, rettangoli e padding dichiarati; scala attenzione pinned uno; shift score `e_score-e_Q-e_K`, shift PV `e_Y-e_Pi-e_V`; [attention.rs](../../rust/volta-pcs/src/c71_matrix/attention.rs) |
| Softcap e token | `C71-SOFTCAP-RNE-v1`, RNE della ricetta pubblica 30·tanh(x/30); argmax dopo softcap, ID minimo a parità. [output.rs](../../rust/volta-pcs/src/c71_matrix/gemma/output.rs) |

Il [riferimento Python](../../scripts/c7_1_gemma_plan.py) implementa
`rms_rne_i16`, `gelu_i16_table`, `softcap_i16_table`,
`gemma_rope_q30_coefficients` e `softmax_exp30_table`.
Le tabelle usano intervalli numerici certificati; un arrotondamento
non risolto respinge la preparazione pubblica. I 65.535 input i16 sono
indicizzati con x+32767; GELU e softcap emettono i16 little-endian.
Il [generatore](../../scripts/c71_calibrate.py) produce complessivamente
24.414.870 byte di tabelle, nell'ordine imposto dal lettore nativo.

RoPE segue precisamente la ricetta intera Q96, dieci termini e quattordici
passi di raddoppio dell'angolo del riferimento, poi RNE a Q30. La ricetta
definisce i coefficienti del modello: non promette l'uguaglianza con una
libreria trigonometrica floating o con RNE del seno/coseno reale.

### Softmax EXP30

Per ogni query viva, sugli score i16 originali:

```text
M = max(score_j sulle posizioni ammesse)
D_j = M - score_j
E_j = RNE(2^30 * exp(-D_j * 2^e_score))
Z = somma degli E_j sulle posizioni ammesse
Pi_j = RNE(2^14 * E_j / Z) sulle posizioni ammesse, zero sulle altre
```

La tabella ha 65.535 output i32, con input D−32767 e byte biased D+1.
E(0)=2^30 garantisce `2^30 ≤ Z ≤ 450·2^30 < 2^39`.
Questa è la funzione intera selezionata: non coincide sempre con RNE
della softmax reale. Il [caller](../../rust/volta-pcs/src/c71_matrix/gemma/softmax.rs)
prova massimo, differenze, lookup, somma e rapporto sugli originali.
Il padding query interno ha D=0, E=2^30, Z=Pi=0; il suffisso esterno
alla sorgente A è invece zero. Gli istogrammi includono le visite pubbliche
al padding interno: `32*106*(O+150)` per istogramma EXP30.

### Copertura e ordine causale

[canonical.rs](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical.rs)
deriva 2.328 produttori e 3.471 sorgenti A, verificando unicità, dipendenze
e dieci alias globali K/V prima della normalizzazione. Le 1.435 sorgenti
semantiche comprendono 892 output RNE, 421 RMS, 60 GELU, 60 Pi, softcap
ed embedding. I 773 gruppi P0 leggono i 772 tensori fisici W.

Le 410 RNE su richieste originali riusano key e punto del consumatore;
le altre 482 usano sonde dei valori originali. Le liste sono disgiunte.
[canonical_prepare.rs](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_prepare.rs)
esegue le righe dei produttori nell'ordine causale. Le righe logits 99–148
determinano i token 100–149; il token 149 completa KV senza un altro output.
Un errore di un consumer non pubblica un token parziale.

### Calibrazione prima dell'installazione

[c7_d126_gemma_weight_ingest.py](../../scripts/c7_d126_gemma_weight_ingest.py)
con [gemma31b_bf16_pack.rs](../../rust/volta-pcs/examples/gemma31b_bf16_pack.rs)
deriva gli esponenti W minimi compatibili con RNE, verifica gli stessi
byte BF16 sottoposti a hash e pubblica il packed atomicamente.
[c71_activation_pilot.py](../../scripts/c71_activation_pilot.py) usa W
dequantizzata, DAG nativo e KV causale floating per proporre una sola
mappa A sui tre contesti, con un bit di margine sugli estremi osservati.
Questo calcolo approssimato inizializza le scale; non certifica Γ.

[canonical_calibration.rs](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_calibration.rs)
esegue invece gli operatori interi: legge W packed con una cache di riga,
conserva solo le righe A vive, raccoglie intervalli e istogrammi e mantiene
KV i16 causale. Rilascia ogni riga dopo l'ultimo consumer; trasferisce KV
al contesto successivo solo dopo tutti i 150 token e la copertura di ogni
sorgente, inclusi padding e istogrammi.
[canonical_calibration_input.rs](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_calibration_input.rs)
implementa l'interfaccia nativa da file; il wrapper Python genera le
tabelle certificate e verifica l'hash del packed contro il report
d'ingest. La sola CLI Rust non certifica queste due proprietà.
Lo storage offline non è l'arena della prova; workspace dei produttori
e allocator restano distinti dai payload nominati. Confronto indipendente
e congelamento seguono [runpod-tests](runpod-tests.md#validazione-e-congelamento-del-profilo).

### Confronto indipendente

L'export dei valori è disponibile. `c71_calibration run-trace` e il modo
`trace` del [wrapper](../../scripts/c71_calibrate.py) producono `C71TRC01`
durante lo stesso replay intero: `Trial::emit` scrive le righe prima del
rilascio, `Trial::finish` scrive padding e istogrammi, `fixed_run` scrive
token e KV finale. I frame portano contesto, sorgente, coordinate, forma,
ripetizione e codec originale da 1–8 byte; il padding è compatto. Il writer
usa scratch limitato, un footer con censimenti e BLAKE3 e il wrapper pubblica
la traccia privata con permessi `0600` solo dopo exit 0, validazione e
confronto indipendente esatto, senza overwrite.

[c71_calibration_trace.py](../../scripts/c71_calibration_trace.py) verifica
in streaming framing, metadati senza chiavi duplicate, tre contesti,
geometrie e copertura completa delle sorgenti dichiarate, coerenza dei
metadati fra contesti, digest delle ricette, padding, istogrammi, token,
KV finale, censimenti, footer, EOF e SHA-256. Può anche confrontare ogni
frame di dati con un flusso atteso; le fixture ridotte respingono valori alterati,
omissioni, duplicazioni, coordinate errate e troncamenti.

`c71_calibration oracle-plan CANDIDATE` esporta per O=0/150/300 sorgenti,
codec, forme, layout e riferimenti W, sorgenti KV e il DAG topologico con
parametri esatti dei 13 tipi di operatore. Il wrapper rifiuta chiavi JSON
duplicate, intervalli W non contigui, ID o riferimenti fuori dominio,
produttori doppi, copertura incompleta, parametri/arità non canonici e
divergenze del DAG fra contesti. L'export dichiara
`independent_numeric_execution_complete:false`: descrive il calcolo ma non
lo esegue indipendentemente.
Il wrapper passa questo piano al validatore della traccia: le colonne delle
sorgenti attention crescono col prefisso e devono coincidere col rispettivo
contesto, mentre ID, nomi, righe e codec restano comuni. Il
[record della correzione](../../benchmarks/results/c71-trace-context-shapes-2026-10-02-b634e781795d.json)
conserva la regressione che avrebbe respinto una traccia reale valida a O=150.

Il [driver indipendente](../../scripts/c71_calibration_oracle_driver.py)
applica il piano a tutti i 13 tipi di operatore, mantiene solo le righe vive
e KV, ricostruisce padding, istogrammi e token e produce i frame attesi in
streaming. Matrici, QK e PV usano binary64 soltanto dopo il bound assoluto
`<2^53`; RMS usa il piccolo kernel C11 indipendente
[c71_oracle_rms.c](../../scripts/c71_oracle_rms.c), con confronti esatti a
192 bit. Il kernel viene compilato in una directory temporanea privata e il
report registra SHA-256 di sorgente e shared object caricato.

La modalità `trace` confronta ogni frame col driver e richiede
`exact_comparison_complete:true` e `independent_oracle.complete:true` prima
di pubblicare traccia e report. I test ridotti coprono i 13 operatori,
schedulazione causale e rifiuti; l'audit del piano copre tutti i 3471 ID nei
tre contesti. Il driver non è stato eseguito sui pesi reali e non ha ancora
una misura completa di tempo/RSS. La validazione strutturale, il solo audit
locale e un secondo replay Rust non ammettono Γ. L'esecuzione reale deve
soddisfare questo contratto:

- Confrontare gli interi esatti con un calcolo Python indipendente,
  riusando i riferimenti numerici della [semantica](#semantica-numerica)
  e completando quelli mancanti. Coprire accumuli e arrotondamenti,
  RMS, lookup, routing, padding, istogrammi, token e KV incluso l'ultimo
  token. Rilanciare Rust o usare il pilot floating non è indipendenza.
- Legare il report a candidata, packed, workload, tabelle e binari tramite
  digest; dichiarare copertura attesa/ottenuta per sorgente nei tre contesti,
  esito del confronto e primo errore. Confronti parziali, ID mancanti o
  duplicati, coordinate errate, overflow e file troncati non ammettono Γ.
- Elaborare per righe/blocchi con memoria e output limitati: nessuna A
  canonica completa in RAM. I valori sono privati e restano fuori da Git
  e dal transcript del protocollo; conservare solo evidenze piccole
  revisionate. Tempo, disco e memoria del confronto vanno nel preventivo
  della campagna, non in un prolungamento implicito.

Le fixture ridotte producono gli interi attesi con
[c71_calibration_oracle.py](../../scripts/c71_calibration_oracle.py), senza
richiamare il replay Rust. Questa parità di operatori non sostituisce il
confronto completo sui pesi reali o il conto delle risorse. Il
[record del driver](../../benchmarks/results/c71-independent-driver-2026-10-02-645e855645d8.json)
ha esito `PASS_LOCAL_IMPLEMENTATION_ONLY` e lascia esplicitamente aperti
runtime completo e ammissione di Γ.
Il [record del piano pubblico](../../benchmarks/results/c71-oracle-plan-2026-10-02-55423e496cfc.json)
conserva censimenti e controlli fail-closed, con esito `PASS_PLAN_ONLY`.

## Dati autenticati e stato

Il campo base è Goldilocks `p=2^64-2^32+1`. I MAC usano
`Fp3=Fp[u]/(u^3-2)`, con 8 byte per elemento base e 24 per elemento Fp3.
La convenzione è `k=m+Delta*x`. Il bootstrap usa il segno opposto:
l'[adapter del pool](../../rust/volta-pcs/src/c71_matrix/gemma/native/pool.rs)
nega Delta una volta e raccoglie tre righe base consecutive per Fp3.
I tag privati grezzi non vengono comunicati al verificatore.

W ha layout `Flat(D35)` e range i16 simmetrico; A ha `Flat(D34)` e range
byte. L'ordine Boolean è MSB. Il suffisso esterno è nullo; il padding
dei rettangoli interni è verificato separatamente dai produttori.
Il preparatore fissa raw, byte, istogrammi, token e KV prima di C_A,
senza chiavi, MAC o sfide future. Il getter ricostruisce questi stessi
valori e non può leggere correlazioni non consumate.

Il registro conserva Γ, C_W, sessione, epoch, seal, cursore, slot e A
accettate in ordine. La [macchina matematica](security.md#2-preparatore-e-macchina-di-accettazione)
definisce l'accettazione; il wrapper nativo brucia la riserva prima del
decoding e registra il successo prima della promozione. Le correlazioni
di ogni nuova apertura sono fresche anche quando la root è storica.
La capacità `Acceptance` resta interna. Il
[record di completamento](../../rust/volta-pcs/src/c71_matrix/gemma/native/acceptance_transport.rs)
usa 73 byte: dominio `C71ACC01`, esito, hash del certificato pendente e
ricevuta FS. Non trasporta roots, token o storia da importare. V lo emette
dopo il journal; P confronta entrambi i digest prima del proprio journal
e della promozione. Errori di invio, troncamenti e differenze terminano il
run. Il codec non autentica il mittente: canale autenticato dedicato e
journal non riportabile indietro restano premesse del chiamante.

## Ordine e formato del certificato

La [schedule completa](security.md#3-schedule-completa-e-destinazione-degli-endpoint)
è implementata da
[canonical_verify.rs](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_verify.rs)
e dal corrispondente corpo CPU
[canonical_prove.rs](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_prove.rs).
Il prover controlla contesto, sorgenti originali e riserva prima dei callback
privati; usa gli stessi operatori, frame e MAC del verificatore. Questo
collegamento non è ancora una verifica positiva di certificati canonici.
I target finali sono 775 per W, 4.446 per A corrente e uno per ogni A
precedente. Nessun endpoint può restare privo della sua apertura originale.

| Frame | Contenuto |
|---|---|
| 0–7 | Forme pubbliche, P0, RMS, RNE originali, RNE con sonde, GELU, gate-up, RoPE |
| 8–127 | QK/PV, in coppia per i 60 layer |
| 128–132 | KV, softcap, EXP30, range W, range A |
| 133 e successivi | PCS W, A precedenti in ordine, A corrente |

I [frame canonici](../../rust/volta-pcs/src/c71_matrix/gemma/native/protocol.rs),
con [fixture di codec](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_wire.rs),
hanno ordine u16, lunghezza u32 e payload canonico; il record finale
vincola conteggio e lunghezza e richiede EOF. Si hanno 135/136/137 frame.
Un solo FS lega Γ, roots, registro, sessione/epoch/seal, slot/intervallo,
nonce, prompt e tutti i token; dominio `C71B12-Gemma-FixedRun-v1`.

Il cap della risposta canonica è 96 MiB e quello di ogni PCS D34/D35
16 MiB. Il percorso ridotto mantiene 16 MiB e 8 MiB rispettivamente.
I cap sono limiti del parser, inclusi nel contesto pubblico, non obiettivi
di comunicazione. Le due configurazioni gamma canoniche hanno 2.277 byte
ciascuna; l'header completo ha `5875+720*slot` byte.
Il wrapper limita il transcript a 2^42 richieste FS: è un arresto
operativo derivato dall'analisi, non un conteggio misurato delle chiamate.

| O | Limite inferiore del corpo completo | Limite superiore del corpo completo |
|---:|---:|---:|
| 0 | 47.841.180 B | 65.053.244 B |
| 150 | 54.868.318 B | 78.945.726 B |
| 300 | 61.797.384 B | 92.723.304 B |

I conteggi di `b12_native_wire_body_envelope` e `b12_native_linear_pcs_wire`
nel riferimento Python includono header e PCS, ma escludono bootstrap e
gli altri dati di installazione/sessione. Il limite inferiore omette
GKR congiunti e fratelli Merkle; non è una dimensione ottenuta.
Il [codec](../../rust/volta-pcs/src/c71_matrix/codec.rs) è controllato
con fixture sintattiche complete da 64.638.068/78.530.550/92.308.128 B;
queste non sono certificati crittograficamente validi.

## PCS e ricostruzione dei valori

La PCS conserva `t_i=t_zk=512`, 1.536 pad iniziali, 512 successivi,
`ell_zk=2048`, `r_zk=512`, `H_zk=32768`,
`H=next_power_of_two(8*(M+r))`, `tau=H/4`. Root salate, query e pad
seguono il budget congiunto di esposizioni in [security](security.md).
Per sessioni ulteriori non è autorizzato il riuso illimitato dei sali/pad.

[ReplayModel e Code](../../rust/volta-pcs/src/c71_matrix/b12/replay.rs)
conservano dal primo commitment cache Merkle superiore, stato/offset dei
sali e pad privati. Gli handle condividono la cache immutabile; la prova
non ricostruisce il commitment iniziale. Le sue monete successive e i MAC
sono freschi. W numerica e getter PCS condividono un solo packed immutabile.

L'[albero Merkle](../../rust/volta-pcs/src/c71_matrix/b12/replay_tree.rs)
conserva la geometria ridotta fino ad altezza 2^18. Per le sole colonne
iniziali W/A ammette ora altezze 2^32/2^31, 128 colonne base, coset 2^22
e taglio Merkle 2^12: rispettivamente 1.024/512 passaggi. Gli stadi extension
grandi hanno 12 colonne base: S1 usa coset 2^24, S2 2^22, S3 e successori
al più 2^23, sempre con taglio 2^12. Le altezze dei due profili nativi
determinano lo stadio; i test le ricavano dalla configurazione WHIR.
Geometrie grandi diverse, inclusi S3 a 2^24 e i coset A che causerebbero
1.024 ricostruzioni, falliscono
prima dell'allocazione o del consumo dei sali. Questo sostituisce il
precedente rifiuto iniziale registrato nel
[checkpoint della strumentazione](../../benchmarks/results/c71-runner-measurements-local-2026-10-03-187a0b9dc9ce.json).
I sottoalberi delle query sono raggruppati fino a 1.024 righe nel riferimento
piccolo e 2^21 nei percorsi canonici grandi; le query pubbliche restano
al più 1.024. Le stesse righe alimentano hash e aperture, ripristinando
ordine e duplicati. Il limite grande è collegato ma non eseguito: resti,
albero dei fattori, strutture intermedie e multipunto CPU non costituiscono
ancora la pipeline canonica GPU a workspace limitato.

Il coset base accumula `(indice originale, valore)` in un unico buffer
column-major, indipendentemente dall'ordine causale dei produttori.
Potenze fattorizzate in due tabelle piccole mantengono i pad alle posizioni
originali, oltre la lunghezza completa della colonna, non oltre il solo
prefisso vivo. Una colonna FFT viene riusata senza copia di un'intera
matrice; entrambi i twiddle P3 rimangono allocati fra coset. Lo scanner A
non riceve monete PCS, sfide o correlazioni. Il getter scalare resta per
W packed e per i consumer non ancora convertiti. Le regressioni e i limiti
sono nel [checkpoint](../c7.1-history/canonical-initial-scan.md).

Per il prodotto Z dei punti richiesti, i coefficienti sorgente vengono
ridotti a blocchi modulo Z. Prodotti FFT bilanciati costruiscono Z;
l'inversione di Newton costruisce il reciproco; un albero di resti
produce le valutazioni. Gli owner iniziali forniscono il prefisso vivo
del layout. Si separano payload, zeri pubblici e `X^M*pad` alle posizioni
originali; i pad non vengono spostati. Gli oracoli successivi al fold
mantengono l'intero supporto, senza ereditare zeri non dimostrati.

Le query della A originale ricostruiscono ora finestre byte di due
colonne, con cap 256 MiB: il caso D34 ha colonne da 2^27 byte. I blocchi
di ogni colonna sono consumati high-to-low nella stessa finestra già
prodotta, inclusa la seconda colonna. Il callback legge soltanto il
prefisso vivo; zeri esterni e pad PCS sono aggiunti dal codice dei resti.
Il buffer appartiene al singolo batch di apertura, non agli snapshot
storici. Una ricostruzione fallita interrompe il batch; valori alterati
non possono aprire il root Merkle conservato. Le finestre del preparatore
usano ora gli stessi controlli di copertura per riga dello scanner iniziale.
L'output è scritto direttamente nei limb base restituiti all'albero,
senza una matrice `Coefficient` completa aggiuntiva. Al cap iniziale ciò
rimuove una copia nominale da 2 GiB, non dimostra il picco completo.
Il [checkpoint delle query](../c7.1-history/canonical-query-windows.md)
separa le verifiche ridotte dal lavoro restante sui workspace.

Coset, resti e correzione dei pad di colonne base usano elementi da 8 B;
quelli extension da 24 B. La conversione base rifiuta coordinate extension
nonzero. La PCS nativa usa la base cubica `v^3-v-1`: non reinterpretare
i suoi tre limb come quelli MAC `u^3-2`. Le conversioni esistenti nel
[modulo di conversione](../../rust/volta-pcs/src/c71_matrix.rs), `to_p3` e
`from_p3`, e i test del
confine Rust/C++ sono parte del contratto.

Il [residuale](../../rust/volta-pcs/src/c71_matrix/b12/sourcewise.rs)
fattorizza Eq e genera i pesi Pow tramite P/Q e FFT, in blocchi nativi
al più 2^21. Gestisce punti zero/uno e scale zero. Per la sorgente A con
scanner, singleton, valutazioni MLE, coset S1, OOD e rigenerazione S1
accumulano mappe lineari in ordine sorgente: ogni byte contribuisce
all'indice folded con il peso Eq del prefisso MSB già fissato. Non sono
valori folded distinti: più contributi allo stesso indice si sommano.
Il suffisso pubblico zero non richiede emissioni. L'OOD usa potenze
fattorizzate, mantenendo i pad dopo la lunghezza completa del messaggio.
Non si fondono scansioni attraverso root/OOD o altre sfide FS.
Il coset extension accumula direttamente tre colonne base per elemento
nativo, riusando la colonna FFT e i due twiddle; non alloca una seconda
matrice intera interleaved/row-major. Il vecchio percorso denso resta
solo come oracolo di test. Una scansione fallita non installa S1 parziale;
il fold successivo richiede prima la retention. Dopo questa, il residuale
legge S1 e non richiama lo scanner originale. Ciò non prova il rilascio
fisico di checkpoint o degli altri owner che conservano gli snapshot.
Il [checkpoint delle riduzioni](../c7.1-history/canonical-residual-scan.md)
conserva il confronto ridotto con transcript e MAC originali.
Q, spettro inverso, avanzamenti e twiddle sono ora trattenuti fra le due
sfide adattive: fold e scaling modificano le ampiezze, non le basi. Dopo
il secondo fold lo stato elimina tale owner prima del nuovo commitment;
le nuove basi invalidano sempre la preparazione precedente. Un blocco
finale più corto usa soltanto il prefisso della serie già preparata.
`State::new` ammette fino a D35, con prefisso iniziale al più sette bit
oltre D16, senza allocare Eq o sorgenti complete. Il conto `named_bytes`
include capacità e descrittori dei vettori P/Q trattenuti e un upper dei
payload dei due twiddle; non è un picco fisico, non include tutto il
workspace temporaneo né allocator/runtime. Il
[checkpoint degli stadi](../c7.1-history/canonical-pcs-stages.md)
documenta geometrie e lifecycle. Le shape canoniche non sono eseguite,
la contabilità completa e il collegamento CUDA restano lavoro locale.
Per A ordinata S1 rimane allocato; il predecessore viene interrogato e
rilasciato prima di modificare lo stato successivo. W non seleziona S1.

[c71_fft_microbench.cu](../../cuda/c71_fft_microbench.cu) contiene FFT
diretta/inversa, normalizzazione 1/N, geometrie pari/dispari e riferimento
dei resti a quattro FFT. Due tabelle twiddle coesistono: `32*B` byte,
64 MiB al cap B=2^21. I confronti Rust/C++ usano spettri nativi, pad e
tre colonne base per Fp3. Il percorso host è verificato; quello CUDA
è compilato, senza una verifica GPU acquisita.

## Preparazione e prova a memoria limitata

[canonical_ordered.rs](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_ordered.rs)
implementa il riferimento CPU canonico: il driver numerico prepara tutti
i token, conserva KV e istogrammi completi e cattura i 61 checkpoint di
layer. Una sola generazione è condivisa fra A corrente e precedenti; la
ricostruzione deve riprodurre token, KV e digest dello snapshot. Il getter
risolve le dipendenze, rilascia le righe dopo l'ultimo uso e distingue il
padding interno dall'assenza di celle nel dominio PCS. Non materializza A
completa. `scan_original` emette ogni sorgente richiesta una volta per
coset, con bitmap di copertura delle righe e indice delle tessere per
sorgente; propaga subito gli errori del consumer. Padding interno biased,
istogrammi, KV e checkpoint sono emessi dai loro owner immutabili; il
suffisso esterno rimane zero pubblico. Il commitment A chiama questo
scanner 512 volte secondo la geometria, non la finestra scalare da 128
byte. Anche le prime query PCS usano il lettore a finestre descritto sopra;
le riduzioni lineari del primo stato PCS usano ora lo scanner sorgente.
Getter scalare e replay per riga restano nei consumer non convertiti.
La ricostruzione di uno snapshot completo procede ora in ordine
topologico dei producer: tutte le righe di un operatore precedono il
consumer successivo, e solo allora si rilasciano i suoi ultimi input.
Token e KV sono già immutabili; la preparazione iniziale e la rigenerazione
dei checkpoint restano token-causali. Il batch matriciale comune a
`prepare_row` e allo scanner valida input i16, raw i48, shape W e offset
di selezione lm_head. Emette raw consecutivi senza RNE o pad aggiunti.
Nel riferimento CPU legge ciascun coefficiente W una volta per batch e
lo applica a tutte le righe, senza saltare gli input zero. Il budget prima
di letture/allocazioni comprende input i16, output raw e una seconda
capacità raw per il trasferimento nelle righe vive dello scanner.
Questa capacità aggiuntiva e i payload delle altre righe sono controlli
locali, non il picco simultaneo completo. Il descrittore espone anche
l'offset packed W. Il nuovo adapter Matrix/RNE usa questo descrittore
sugli handle nativi, ma lo scanner complessivo rimane CPU: il percorso
GPU non deve scaricare questi `Vec` come spill dello stato.
`Prepared::range_window` implementa il reader per
finestre dyadic allineate, fino a 2 GiB, nell'ordine
`[tail][prefisso folded][u Gram][sottoalbero]`. Seleziona le sorgenti
intersecando le maschere dei bit fissi delle tessere con quelle della
finestra riordinata, quindi riusa `scan_sources` e la sua verifica di
copertura. Non enumera il dominio per decidere i producer. Le finestre
devono contenere interi sottoalberi; forme, overflow e budget sono
controllati prima di toccare l'output. Un errore durante lo scan invalida
l'output parziale. Il consumer CPU
[range/windowed.rs](../../rust/volta-pcs/src/c71_matrix/range/windowed.rs)
è ora collegato al range A canonico tramite `SourceModel::range`.
Conserva il canopy sopra un taglio di dieci bit; i livelli inferiori
usano le composizioni Gram selezionate e trattengono al massimo 2^24
tuple di quattro figli in D34. Il buffer byte è al più 2 GiB. H termina
prima della retention, i livelli canopy consumati sono rilasciati e
`truncate` dei figli non ne libera la capacità. Le uguaglianze vengono
calcolate per indice, senza un Eq(N) denso. È ancora aritmetica CPU.

Il medesimo motore serve W signed, senza bias: `Plan::range_window`
enumera solo l'intersezione fra tessera e finestra permutata, legge dal
packed originale condiviso e inserisce il suffisso zero pubblico.
Conserva cut=11/m24 e le composizioni Gram W selezionate (29 passate D35),
con staging al più 2^27 parole i16, ossia 256 MiB. Il piano cut=10/m25
precedente non viene riammesso. L'istogramma di 65.535 contatori u64
(524.280 byte logici) è calcolato una volta all'installazione, nella fase
`installation_w_commitment`, e include il padding nel bin 32.767.
I contatori sono riusati, le righe MAC no. Il reader condivide lo stesso
owner packed del commitment; rifiuta i16::MIN e geometrie errate.
Questo collegamento CPU non implementa i kernel CUDA specializzati né
conferma il conto fisico completo o i tempi dello screen storico.

[c71_range_native.cu](../../cuda/c71_range_native.cu) avvia il port CUDA
di questo evaluator con la stessa rappresentazione Fp3. I gruppi originali
sono limitati a 2^11 valori; il payload shared dinamico massimo è 52.224 B,
comprensivo dei figli per u. I root strided evitano sovrascritture fra thread
durante la riduzione. H usa bucket limitati e somme modulari CAS per limb;
i suoi fold usano buffer distinti, non la compattazione CPU in-place.
Le riduzioni dei coefficienti richiedono 256 thread e 24.576 B shared.
Il kernel coefficienti compilato usa inoltre stack locale, da contabilizzare.
L'[owner nativo](../../cuda/c71_range_runtime.cpp) usa device esplicito,
stream privato e una sola arena, senza malloc per buffer o spill host.
I 64 descrittori hanno handle monouso, tipi, copertura inizializzata e
capacità allineate a 256 B. Il fold riduce la lunghezza, non la capacità;
il release ritira l'handle, non libera l'arena, riusabile in ordine sullo
stesso stream. Solo `cudaFree` riuscito azzera la prenotazione nel report
di chiusura; un errore di cleanup resta esplicito e conservativo.
Il chiamante serializza ogni contesto e include arena e riserva nel budget
globale: il cap locale 6.442.450.944 B non autorizza arene concorrenti.
Le fixture piccole scelgono una riserva ridotta; il percorso canonico dovrà
garantire almeno 256 MiB e la contabilità con gli altri owner.
Upload e download sono fenced; solo root/terminali e quattro coefficienti
possono tornare all'host, dopo il successo e il controllo dei limb.
Errori di shape, handle, CUDA o fence fermano definitivamente il contesto.
Il ledger conta prenotazione richiesta, capacità assegnate/picco, payload,
byte copy/zero sottoposti e tentativi di launch/fence. Non misura il bus
né driver, context, staging CUDA, stack/shared o il picco dell'intera prova.
Il [consumer Rust](../../rust/volta-pcs/src/c71_matrix/range/windowed/native.rs)
collega l'ABI nativa al corpo di prova range condiviso. `Source.native`
seleziona esplicitamente libreria locale fidata, device, arena/riserva,
finestra originale e bucket H. L'ABI è controllata prima di creare l'owner;
la rappresentazione Rust Fp3 non viene reinterpretata: si copiano i limb
canonici tramite strutture C. Solo u8/i16 implementano il tipo di upload.
L'owner vive fino alla fine della prova range; il cleanup riuscito è
richiesto prima di restituire la prova. Gli errori non selezionano CPU.
Canopy e figli condividono lo stesso buffer nativo quando cambia la vista;
H usa fold distinti, rilasciati in ordine sullo stream. Le finestre host
vengono riusate solo dopo il fence di upload. `Work.native` espone il ledger
parziale dell'owner, non una misura fisica completa. Il runner conserva
la configurazione CPU esplicita precedente e non ammette ancora GPU E2E.

Il primo scan completo del commitment byte conserva 256 contatori u64,
con il suffisso esterno aggiunto al bin zero; l'istogramma è installato
solo dopo il successo di produttore e consumer. I successivi scan non
lo ricostruiscono, quindi le 512 ricostruzioni iniziali non aumentano.
Il contratto interno di immutabilità/unicità resta quello dello scanner;
il conteggio da solo non prova l'unicità. Un reader range viene installato
solo con un istogramma completo. Questi contatori e la loro copia nella
sorgente range restano capacità vive da contare. Il reader non vede monete
o correlazioni; i callback aritmetici fallibili interrompono il protocollo
prima dell'autenticazione successiva. Non esiste fallback scalare su errore.

Il [checkpoint del consumer](../c7.1-history/canonical-windowed-range.md)
distingue le passate eseguite su input ridotti dalle 26 selezionate per
D34. Il ledger interno misura passate, byte richiesti, merge e payload
nominati dell'evaluator, non il lavoro completo del preparatore o il
picco fisico con PCS/Seed6/verificatore. I
[controlli del gather](../c7.1-history/canonical-range-gather.md)
non eseguono una finestra da 2 GiB o la prova D34.
Il limite di preparazione controlla payload nominati, non il picco fisico
complessivo. Coset, frontier/sali/cache Merkle, colonna FFT, due twiddle,
potenze, bitmap, metadata, checkpoint e workspace numerico vanno contati
simultaneamente con gli altri owner; il subtotal Merkle non li include
tutti. Non è una misura GPU né una verifica delle shape complete.

[ordered.rs](../../rust/volta-pcs/src/c71_matrix/gemma/native/ordered.rs)
è il riferimento ridotto: scopre i token dai logits, valida i produttori,
conserva cut/KV immutabili e una finestra byte. La sua storia numerica
copre O=0/2/4; il positivo con prova ordinata e Seed6 copre O=0.
Un candidato con due tentativi ordinati sullo stesso pool Seed6 reale ha
completato il primo e raggiunto `range_A` del secondo, poi ha superato il
limite locale di 60 s; il [record negativo](../../benchmarks/results/c71-real-two-attempts-2026-10-03-262e89febe2c.json)
non attribuisce copertura multi tentativo.
La ricostruzione ricorsiva CPU non implementa la schedule canonica 512.

Il [runner CPU esplicito](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_runner.rs)
collega preparazione, PCS W/A, Seed6 ell=11 e tre risposte sullo stesso
registro mediante socketpair locali. Richiede input canonici e non è
ammesso sulla VM di sviluppo. Non certifica numericamente le tabelle né
la provenienza del packed. Trasmette ora candidata e tabelle esatte con
`C71PUB01`, root W/identità/sessione con `C71INS01` e ciascuna richiesta
con `C71REQ01`. Il verificatore ricompila un profilo proprio dai byte
ricevuti prima dell'installazione. I cap precedono le allocazioni del
decoder: candidata ≤1 MiB, tabelle esattamente 24.414.870 B, installazione
136 B, richiesta 416 B. Il framing della risposta aggiunge 680 B al corpo;
il completamento ne usa 73. Sono dati sul canale locale autenticato,
non una nuova autenticazione crittografica del trasporto.

[canonical_metrics.rs](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_metrics.rs)
conta i byte effettivamente letti/scritti dal lato V, separando
distribuzione, installazione, Seed6 e ogni risposta. I primi tre gruppi
sono addebitati una volta al primo tentativo, senza ammortamento.
Il tempo parte prima della lettura di Γ; le fasi distinguono compilazione
dei due ruoli, caricamento W, commitment W/A, preparazione, corpo della
prova, attesa/decoding, verifica e completamento con journal. Gli intervalli
wall sono annidati e i ruoli concorrenti: non si sommano per ottenere un
tempo totale. La preparazione fonde inferenza, istogrammi e checkpoint;
`inference_wall_ns` e `proof_only_wall_ns` restano `null`, con
`phase_partition_complete:false`, finché questi costi non sono separati.
Il costo dopo la preparazione non è presentato come tutta la prova.
In caso di errore il runner emette su stderr `C71_RUN_METRICS` con fasi
incomplete e traffico parziale, senza valori privati; un processo ucciso
richiede comunque il log del controller. RSS/HWM sono dell'intero processo
host con entrambi i ruoli, non picchi per fase, CPU-time o contabilità HBM.
Il driver non offre un percorso GPU né un fallback di produzione.
Rimangono locali l'adattamento dei kernel densi al piano a memoria
limitata, il collegamento CUDA e la contabilità simultanea completa.

Il piano canonico conserva 61 checkpoint di layer, 98.380.800 B per
una generazione alla volta. Raw e output arrotondato sono distinti.
Range usa finestre da 2 GiB, le prime query A finestre da 256 MiB.
Nel commitment A il coset è 2^22, con 512 ricostruzioni; lo slot reader
è riusato per hash salato nelle celle già consumate, con fence prima
del riuso. S2 è 2^22 e i successori al più 2^23. La capacità S1 resta
riservata fino all'ultimo consumer: `truncate` non la libera.

Il [kernel denso i16](../../cuda/c71_dense_i16.cu) implementa il prodotto
intero selezionato nel [preflight storico](../c7.1-history/preflight.md):
`x=256*h+l+128`, quattro dot INT8 signed e correzione mediante le somme
originali delle righe. X e W restano row-major `[M,K]` e `[N,K]`, senza
trasporre o espandere globalmente W. Ogni warp usa MMA densa m16n8k32,
quattro warp per CTA e output 16x32; i frammenti seguono le
[coordinate PTX NVIDIA](https://docs.nvidia.com/cuda/parallel-thread-execution/index.html#warp-level-matrix-fragment-mma-16832).
K≤21.504, M≤150 e N≤262.144; ogni accumulatore INT8 ha modulo al più
352.321.536, senza saturazione. La ricomposizione i64 usa anche il padding
K a multipli di 32, che deve annullarsi esattamente per originali zero.
Il risultato raw precede un kernel RNE separato che conserva tutte le
classi di `rne::integer`: raw signed-48, pareggi al pari, output simmetrico
±32767, shift ≥48 a zero e shift ≤−15 ammesso solo per raw zero. Non clampa.
Il launcher verifica shape, capacità dichiarate, allineamento e alias
scrivibili; consente alias fra input di sola lettura. Il marcatore −32768
imposta un errore device sticky. L'owner deve inizializzarlo e, dopo fence,
verificarlo prima di usare qualsiasi output. Il launcher non alloca,
non sincronizza e non abilita un fallback. L'owner di stream/arena del range
ora collega prodotto e RNE tramite handle distinti; gli output restano
non inizializzati fino a fence e flag valido, e ogni errore ferma il contesto.
W è una sola allocazione globale esterna all'arena, caricata in ordine con
finestre ≤256 MiB e poi sigillata senza sostituzioni o puntatori esportati.
Il cap è 61.394.690.560 B; l'ammissione controlla ≥1 GiB libero prima/dopo
l'allocazione, non promette assenza di allocazioni concorrenti esterne.
Il ledger ABI 3 (152 B) separa W e arena, somma le prenotazioni nel picco
e conserva i byte non liberati su errore di cleanup. Conta anche i 4 B
di flag per operazione; raw e RNE rimangono entrambi addebitati fino al rilascio.
Non scarica gli intermedi sullo host né rialloca W fra i batch.
Il consumer range Rust controlla questa ABI; una catena ridotta Rust/C
confronta RNE con `rne::integer`, poi la root range con gli stessi interi.
L'[adapter residente](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_resident.rs)
collega ora i passi Matrix/RNE selezionati dal piano canonico allo stesso
runtime Rust. W viene installato dalla medesima `Arc<Vec<i16>>` immutabile:
lunghezza packed e digest del layout sono controllati, poi ogni prodotto
richiede lo stesso owner Arc, non soltanto byte uguali. I blocchi opachi
portano ID sorgente, primo indice di riga, dimensioni, layout A e digest
delle ricette. La selezione delle righe passa al launcher come vista
del buffer padre, senza upload/copia o rilascio implicito della capacità.
RNE consuma un intero blocco raw compatibile e restituisce un nuovo handle;
gli errori di metadati Rust fermano anche il contesto C. Gli handle non
sono clonabili e richiedono rilascio esplicito, o cleanup dell'intero owner.
Ogni descrittore trattiene inoltre l'identità `Arc` del runtime Rust:
handle numerici coincidenti di due copie distinte della libreria non
rendono trasferibili i buffer. Il controllo precede consumo e rilascio;
l'owner Rust e i relativi descrittori rimangono memoria host da censire.
Il loader controlla ABI 3 prima di creare un contesto e richiede i simboli
di vista/abort; la precedente ABI 2 da 144 B è rifiutata prima di leggere
il nuovo ledger, che aggiunge `d2d_bytes`.
Il dispatcher di base serve Embedding/Matrix/RNE/Affine/Gate; quello
nonlineare serve GELU/softcap/RoPE/argmax. Norm/QK/softmax/PV restano
assenti: non è un preparatore GPU completo né un fallback.
`NonlinearTables` valida e carica tabelle i16 e due finestre RoPE alle
posizioni assolute del contesto: 8.225.672 B logici, 8.225.792 B allineati
nella stessa arena. Il packing host temporaneo è ancora addebitabile,
oltre alle tabelle pubbliche originali; non è spill privato. Layout,
ricette, posizione e sorgente/righe dell'input sono controllati a ogni
operazione. Ogni istogramma usa 524.280 B logici / 524.288 B riservati e
una bitmap Rust di 150 B (50 per softcap); non è consumabile dal gather
prima del seal completo. Le frequenze rimangono interi nonnegativi:
il bias i32 appartiene esclusivamente al codec byte, come sul riferimento.
GELU/softcap contano anche le ripetizioni, RoPE emette raw signed-48
con coppie mancanti identità Q30 e argmax applica il tie-break all'ID minimo.
Il solo slack ammette −32768. Per batch nonlineare si scaricano 4 B di
flag, più 4 B per token argmax; quest'ultimo usa due fence e un temporaneo
device allineato per gli ID. Il seal istogramma scarica altri 4 B. Nessun
raw, output, istogramma o slack privato viene scaricato. Un raw RoPE
150×32×512 usa 19.660.800 B, oltre a 4.915.200 B di input e altrettanti
per la RNE se simultaneamente vivi. Questi subtotali non sostituiscono
il conto completo: i 64 descrittori dell'owner richiedono ancora una
schedule di rilascio/consolidamento per tutti gli istogrammi della risposta.
Il gather byte nativo ora riusa `Bytes::resident_tiles`,
le medesime tessere di `emit_row_bytes`, su blocchi originali residenti.
`ByteWindow` seleziona sorgenti con le intersezioni pubbliche esistenti;
le bitmap per riga rifiutano duplicati e copertura incompleta. Ogni blocco
deve conservare layout, ricette, sorgente e shape. Il kernel in
[c71_dense_i16.cu](../../cuda/c71_dense_i16.cu), con descrittore
[c71_byte_gather.cuh](../../cuda/c71_byte_gather.cuh), applica il bias solo
al byte alto e la permutazione `[tail][prefisso][u][sottoalbero]`.
Suffix zero fornisce la stessa finestra in ordine originale. Gli input
rimangono residenti; il codice enumera i byte dei soli segmenti di tessere
selezionati, non l'intero dominio A, ma filtra ancora quelli fuori finestra.
L'owner azzera il solo output, riserva un flag sticky per finestra e usa
il tipo pending, rifiutato dal range. Il seal richiede copertura Rust,
fence e flag valido prima di convertirlo in u8; scarica solo 4 B di stato.
Il rilascio anticipato ritira anche il flag senza liberare l'arena. La
copertura del layout è responsabilità del wrapper Rust fidato; l'ABI C
controlla codec, accessi e stato del buffer, non certifica il DAG da sola.
Il loader richiede anche i tre simboli begin/scatter/seal. Mancano ancora
gli operatori rimanenti e il collegamento di questo gather al replay,
lo scanner PCS/range interamente residente, il lifecycle comune del runner
e il conto simultaneo di prover/verificatore/PCS/Seed6. Il ledger C non
comprende i descrittori/bitmap Rust o il picco fisico completo.
Il dispatcher collega anche tutte le ricette `Affine` e i prodotti `Gate`:
riusa `Bytes::affine_shape` per codec, geometrie e coefficienti e richiede
gli input originali nell'ordine delle porte non nulle. Le viste selezionano
righe contigue all'interno di ciascun buffer padre, senza copie. Un kernel
pointwise esegue R=aX+bY oppure R=XY, con input simmetrici i16 e output
i64 contenente il signed-48 originale. I coefficienti sono limitati a
±2^30: le due somme di prodotti non possono uscire da signed-48; il gate
è entro signed-32. Zero coefficienti richiedono handle assenti e non
caricano valori. Raw e output RNE rimangono distinti e addebitati;
fence/flag precedono la pubblicazione, come per Matrix.
Il loader ABI 3 richiede anche `c71_dense_pointwise`.
L'embedding riusa lo stesso descrittore validato dal riferimento CPU:
cohort lookup originale, codec i16, vocabolario, colonne, intervallo di
righe e ID token. Richiede la stessa Arc W installata e il suo layout.
`c71_dense_embedding` verifica tutti gli ID e l'intero span W prima della
prima copia, conserva una lista locale di al più 150 ID e accoda una
`cudaMemcpyAsync` D2D per riga sullo stream privato. Mantiene ordine e
ripetizioni; pubblica l'output solo dopo fence riuscito. W è già stato
validato come i16 simmetrico all'installazione: nessun calcolo o nuovo
kernel, copia W host, upload token device o download intermedio. Il ledger
conta i byte D2D sottoposti con successo anche prima di un errore parziale;
non misura il traffico fisico del bus. Stack host degli ID, overhead del
runtime e tempi restano nel conto globale da completare. Il chiamante
del runner dovrà fornire gli ID dello snapshot causale fissato; l'adapter
non prova da solo quella provenienza. Il loader richiede anche il simbolo
embedding. Restano otto tipi di producer e l'integrazione completa.
Il codec byte condiviso accetta l'intero intervallo signed della propria
larghezza, incluso −32768 per `U/global/argmax_slack`: la prima versione
del gather rifiutava erroneamente questa cella valida. Il rifiuto del
marcatore resta nei confini aritmetici e nell'upload signed ordinario;
il producer argmax residente resta da implementare.
Il modello host dei frammenti non è esecuzione o verifica concorrente CUDA.

RMS usa P/Y originali e S48 condiviso per riga, con checkpoint da
2.023.511.878 B comprensivo dei descrittori. GKR ricostruisce gli
assegnamenti Booleani; l'endpoint byte usa LUT pubbliche anziché alberi
per ogni cella. Il verificatore deve evitare Eq(N) e selettori P*N densi.
Il massimo EXP30 usa un livello da 512 MiB/1 GiB, rilasciato prima di
lookup/GKR. Il lookup conserva query e istogrammi originali e il taglio
superiore dell'albero, ricostruendo quattro livelli.

Il backend nativo EXP30 usa istogrammi privati di pattern a cinque bit,
pesati da Eq sulla posizione originale. Il DAG Boolean condivide alias
e antenati senza modificare circuito o transcript. Il riferimento BMMA
e la contrazione dei nodi byte sono valutazioni degli stessi polinomi,
con confronti ridotti; non sono un backend canonico GPU verificato.
La contrazione mantiene baseline f(0), padding pubblico e recupero dei
quattro figli terminali; i ranghi massimi sono [4,8,16,17,9,5,3,2].
Il percorso nativo contratto accetta domini completi fino a 128 celle.
Le [analisi EXP30](../../scripts/c71_exp30_alternatives.py) e
[byte tree](../../scripts/c71_byte_tree_contraction.py) espongono questi
limiti. Non si trasferisce un limite inferiore di un kernel respinto
a un'implementazione aritmetica differente.

La candidata CUDA corrente usa le primitive con riporti/prestiti espliciti
di [c71_fp3.cuh](../../cuda/c71_fp3.cuh), rappresentanti canonici e campo
invariato. Il confronto host con u128 è disponibile; le istruzioni PTX
richiedono ancora un'esecuzione GPU. Il
[conto congiunto](../../scripts/c71_byte_contract_screen.py) sostituisce
il costo range della precedente aritmetica e conta separatamente getter,
FFT, coda scalare, prefisso BMMA e coefficienti byte, senza sovrapposizioni.
La coda RMS deve essere ricontata con Γ reale; concedere quattro round
iniziali gratuiti al profilo sintetico a scale zero non lo rende fattibile.

Per il requisito a 65 s non usare il main-cell scalare EXP30
`c71_gkr_main_cell_fused`, l'enumerazione letterale della tree byte,
la schedule A a 1.024 ricostruzioni o il layout S3 2^24. Sono percorsi
esclusi per le rispettive risorse; riaprirli richiede un cambiamento del
lavoro o della mappatura aritmetica e una nuova verifica delle stesse
condizioni, non una misura del percorso già escluso. Le motivazioni e
i limiti precisi sono nel [preflight storico](../c7.1-history/preflight.md).

Tutti i consumer nativi prendono intervalli MAC in prestito tramite
`ExactSizeIterator`/`Take`, con cardinalità iniziale e consumo finale
verificati. Non raccolgono una seconda riserva completa in un Vec.
Il burn copre però anche il suffisso non espanso dopo un rifiuto.
Proof, cache, iteratori, output, conversioni e allocator restano memoria
da contare anche quando la copia della riserva è eliminata.

## Correlazioni Seed6

Il riferimento matematico B12 usa `C71B12F1`, suite 3, un setup AES,
profondità GGM fino a 24 e nove sacrifici separati, con capacità e bound
di [security §6](security.md#6-risorse-riuso-formale-e-confine-runtime).
Seed6 è l'estensione efficiente con i parametri e gli obblighi seguenti.

[c71_seed6](../../rust/volta-pcg/src/c71_seed6.rs) e
[c71_ea_lpn](../../rust/volta-pcg/src/c71_ea_lpn.rs) implementano il
riferimento CPU opt-in. Geometria canonica: t=675, h=19, ell=11,
N=353.894.400, capacità 70.778.880. Il setup usa un seed Fp6 principale
da 17.553 righe e uno a ruoli inversi da 2.025. MR19/P-521, COPE AES,
check e compressione precedono il seal e qualsiasi output.

Il guard verifica i cammini sui MAC originali; il primo split cGGM è
indipendente. Le coin di split e F_EQ rispettano commitment prima
dell'apertura. F_EQ usa due chiavi e nove frame; il seed EA deriva dal
prefisso accettato e dalle aperture ordinate per ruolo, nel dominio
`/accepted-EA/`. Non è un parametro sostituibile dal chiamante.
L'accumulatore EA è globale sui blocchi; il batch attraversa i termini
pubblici con gli stessi risultati del riferimento puntuale.

[Lifetime](../../rust/volta-pcg/src/c71_lifetime.rs) registra il setup
prima di RNG/OT, il burn prima di espandere righe e l'accettazione prima
della promozione. Consumo incompleto, panic, errore ignorato o ricevuta
mancante terminano la capacità. L'API usa casualità del sistema e pool
opachi distinti per ruolo; i costruttori ideali sono riservati ai test.
La composizione di sicurezza dell'estensione resta un obbligo esplicito
in [security](security.md#estensione-seed6-e-obblighi-residui).

## Contabilità e criteri di completamento

`T_response_total = T_inference + T_proof_only ≤65 s` per ciascuna risposta.
Tutte le ricostruzioni A/KV, anche se rieseguono inferenza, appartengono
alla prova. Il setup fresco di sessione si registra separatamente e si
addebita una volta alla prima prova e al lavoro dei prefissi. Il caricamento
globale per residenza si registra separatamente. Nessun overlap è gratuito.

Per la comunicazione `P_j=R_j+B_j`: R è il corpo della risposta, B include
ogni altro byte necessario al verificatore e non già addebitato. B1
include installazione e bootstrap offline. Si conta il traffico nei due
sensi; almeno tutti i byte ricevuti dal verificatore entrano nei tetti.
Un riferimento ritrasmesso si paga di nuovo. Il limite di 40 MB non cresce
col turno e non si ammortizza il setup su risposte future.

| Voce del piano | Quantità e interpretazione |
|---|---|
| KV originale i16 | 901.120 B/token; 405.504.000 B per 450 token, coda pendente inclusa |
| W + KV450 + arena | 68.242.645.504 B; residenti/runtime ignoti ancora esclusi |
| Massimi nominati dell'arena a O=0/150/300 | 6.087.512.576 / 6.126.837.504 / 6.166.159.104 B |
| Minimo spazio libero nel piano | 276.291.840 B: solo 7.856.384 B oltre il margine richiesto di 256 MiB |
| Ultimo conto parziale congiunto, primitive con riporti | 45,267005 / 52,813136 / 60,657831 s; non tempi misurati né limiti superiori |
| Budget candidato | 1,5 s inferenza, 17 s getter, 46,5 s resto; obiettivi da verificare |
| Materiale persistente | Riferimento ≤2,10×W=128.928.850.176 B; l'eccezione per materiale globale riutilizzabile non aumenta HBM o arena |
| Verificatore CPU quattro core | Riferimento 6,4–8,2 s da verificare per il percorso completo |

I conteggi eseguibili sono in [arena](../../scripts/c71_arena_plan.py),
[response](../../scripts/c71_response_trace.py), [WHIR](../../scripts/c71_whir_trace.py),
[getter](../../scripts/c71_getter_trace.py) e [PCG](../../scripts/c71_pcg_trace.py).
Il [record del conto congiunto](../../benchmarks/results/c71-carry-field-joint-screen-2026-09-26-8662d88cbb8a.json)
lega i limiti parziali ai binari e alle condizioni esaminate; non include
inferenza, RMS reale e tutte le fasi ancora mancanti. I sottoconti di
getter/PCS precedenti non vanno sommati di nuovo a questo totale.
Il requisito sul lavoro delle sorgenti è `c_source*N + P(q,h)`, con
coefficiente uniforme indipendente da q/N; il solo callback dei resti
non dimostra questo requisito per l'intera PCS. Si contano tutti i batch.

Restano da includere workspace numerici e DFT, hash, spettri, copie,
stato PCG/OT/Fp6, runtime e allocator simultaneamente vivi. Il conto
fisico completo è aperto; un costo ignoto non vale zero. I tre contesti
devono essere ricontati con Γ reale tramite `c71_calibrate.py ledger`.
Il benchmark della prova richiede anche integrazione canonica, input,
SHA pulita, durata/costo e soglie dichiarate in [runpod-tests](runpod-tests.md).

Il verificatore usa al massimo quattro worker complessivi, senza pool
annidati che moltiplichino i thread. Si contano decoding, hash, campo,
GKR/PCS, PCG, MAC e aggiornamento dello stato; registrare tempo CPU e
wall, RSS, affinità e backend AES. Non richiede W, una GPU o un servizio
remoto. Tempi di CPU differenti non sono intercambiabili.
