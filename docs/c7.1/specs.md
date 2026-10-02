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

### Confronto indipendente da implementare

L'export dei valori è disponibile. `c71_calibration run-trace` e il modo
`trace` del [wrapper](../../scripts/c71_calibrate.py) producono `C71TRC01`
durante lo stesso replay intero: `Trial::emit` scrive le righe prima del
rilascio, `Trial::finish` scrive padding e istogrammi, `fixed_run` scrive
token e KV finale. I frame portano contesto, sorgente, coordinate, forma,
ripetizione e codec originale da 1–8 byte; il padding è compatto. Il writer
usa scratch limitato, un footer con censimenti e BLAKE3 e il wrapper pubblica
la traccia privata con permessi `0600` solo dopo exit 0 e validazione,
senza overwrite.

[c71_calibration_trace.py](../../scripts/c71_calibration_trace.py) verifica
in streaming framing, metadati senza chiavi duplicate, tre contesti,
geometrie e copertura completa delle sorgenti dichiarate, coerenza dei
metadati fra contesti, digest delle ricette, padding, istogrammi, token,
KV finale, censimenti, footer, EOF e SHA-256. Può anche confrontare ogni
frame di dati con un flusso atteso; le fixture ridotte respingono valori alterati,
omissioni, duplicazioni, coordinate errate e troncamenti.

Le primitive Python indipendenti e una fixture ridotta coprono matrice
esatta sotto bound binary64, RNE, affine, RMS, RoPE, softmax, rapporto e
argmax, e alimentano l'hook di confronto dei frame. Resta da implementare
il driver che applica queste primitive a tutti gli operatori del modello
reale. La validazione strutturale della traccia,
il confronto dei censimenti e un secondo replay Rust non ammettono Γ. Il
componente mancante deve soddisfare questo contratto:

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

La fixture ridotta produce gli interi attesi con
[c71_calibration_oracle.py](../../scripts/c71_calibration_oracle.py), senza
richiamare il replay Rust. Questa parità di operatori non sostituisce il
driver completo, la sua esecuzione sui pesi reali o il conto delle risorse.

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
La capacità `Acceptance` è interna: il suo trasporto distribuito sicuro
deve ancora essere implementato. Canale autenticato e archivio del journal
non riportabile a uno stato precedente sono premesse del chiamante.

## Ordine e formato del certificato

La [schedule completa](security.md#3-schedule-completa-e-destinazione-degli-endpoint)
è implementata da
[canonical_verify.rs](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_verify.rs).
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
raggruppa sottoalberi in batch di al più 1.024 righe distinte. Le stesse
righe alimentano hash e aperture, ripristinando ordine e duplicati.
Più batch implicano più scansioni della sorgente; il limite nativo 1.024
non equivale al cap canonico pianificato di 2^21.

Per il prodotto Z dei punti richiesti, i coefficienti sorgente vengono
ridotti a blocchi modulo Z. Prodotti FFT bilanciati costruiscono Z;
l'inversione di Newton costruisce il reciproco; un albero di resti
produce le valutazioni. Gli owner iniziali forniscono il prefisso vivo
del layout. Si separano payload, zeri pubblici e `X^M*pad` alle posizioni
originali; i pad non vengono spostati. Gli oracoli successivi al fold
mantengono l'intero supporto, senza ereditare zeri non dimostrati.

Coset, resti e correzione dei pad di colonne base usano elementi da 8 B;
quelli extension da 24 B. La conversione base rifiuta coordinate extension
nonzero. La PCS nativa usa la base cubica `v^3-v-1`: non reinterpretare
i suoi tre limb come quelli MAC `u^3-2`. Le conversioni esistenti nel
[modulo di conversione](../../rust/volta-pcs/src/c71_matrix.rs), `to_p3` e
`from_p3`, e i test del
confine Rust/C++ sono parte del contratto.

Il [residuale](../../rust/volta-pcs/src/c71_matrix/b12/sourcewise.rs)
fattorizza Eq e genera i pesi Pow tramite P/Q e FFT, in blocchi nativi
al più 256. Gestisce punti zero/uno e scale zero. La preparazione P/Q
non è ancora trattenuta fra tutte le sfide adattive canoniche.
Per A ordinata S1 rimane allocato; il predecessore viene interrogato e
rilasciato prima di modificare lo stato successivo. W non seleziona S1.

[c71_fft_microbench.cu](../../cuda/c71_fft_microbench.cu) contiene FFT
diretta/inversa, normalizzazione 1/N, geometrie pari/dispari e riferimento
dei resti a quattro FFT. Due tabelle twiddle coesistono: `32*B` byte,
64 MiB al cap B=2^21. I confronti Rust/C++ usano spettri nativi, pad e
tre colonne base per Fp3. Il percorso host è verificato; quello CUDA
è compilato, senza una verifica GPU acquisita.

## Preparazione e prova a memoria limitata

[ordered.rs](../../rust/volta-pcs/src/c71_matrix/gemma/native/ordered.rs)
è il riferimento ridotto: scopre i token dai logits, valida i produttori,
conserva cut/KV immutabili e una finestra byte. La sua storia numerica
copre O=0/2/4; il positivo con prova ordinata e Seed6 copre O=0.
La ricostruzione ricorsiva CPU non implementa la schedule canonica 512.

Il piano canonico conserva 61 checkpoint di layer, 98.380.800 B per
una generazione alla volta. Raw e output arrotondato sono distinti.
Range usa finestre da 2 GiB, le prime query A finestre da 256 MiB.
Nel commitment A il coset è 2^22, con 512 ricostruzioni; lo slot reader
è riusato per hash salato nelle celle già consumate, con fence prima
del riuso. S2 è 2^22 e i successori al più 2^23. La capacità S1 resta
riservata fino all'ultimo consumer: `truncate` non la libera.

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
