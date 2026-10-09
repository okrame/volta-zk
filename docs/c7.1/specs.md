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
Sono disponibili il riferimento CPU/binary64 e il backend cuBLAS FP64
H100. Γ è ammesso per il workload pinned dal
[record del 7 ottobre](../../benchmarks/results/c71-gamma-admission-2026-10-07-868a3e8.json).
Si riusa dopo i controlli del [runbook](runpod-tests.md#riuso-del-bundle);
questa procedura di calibrazione è necessaria quando Γ viene invalidato.
Confrontare il percorso modificato col riferimento su input fissati,
preservando aritmetica, copertura, ordine causale e rifiuto dei non-finiti.
Registrare backend, configurazione e digest numerici pertinenti. Una
parità ridotta o un guadagno di throughput non sostituisce i cinque
controlli di [ammissione](runpod-tests.md#validazione-e-congelamento-del-profilo).
La telemetria offline conserva contesto, indice del token, operatore,
tempi e lavoro completato anche su errore, senza valori W/A/KV o ragioni
private nel transcript; le prescrizioni sono nel
[runbook](runpod-tests.md#accelerazione-dellinizializzatore).

Il pilot salva ora `progress.jsonl` privato, flush/fsync a ogni token e
al primo confine operatore/blocco dopo un secondo. Il report finale
conserva anche su errore tempi per ID operatore e contatori parziali;
un kill conserva solo i campioni già scritti. Lettura/validazione,
conversione W e dot espongono secondi-worker cumulativi, che possono
sovrapporsi e non vanno sommati al wall. Le misure hardware e la loro
provenienza sono distinte dalle fixture locali.
Il modo `profile --profile-tokens N` esegue un prefisso causale fissato
del medesimo workload per confronti a lavoro uguale. Conserva osservazioni
private e metriche, ma restituisce `complete:false`, `profile_only:true`
e nessuna candidata; non sostituisce il modo `run` completo.
Il report privato del profilo include SHA-256 degli output binary64
little-endian, con framing di posizione, ID operatore e lunghezza.
Permette confronti bit per bit del flusso completo sul prefisso misurato;
non è un commitment del protocollo né evidenza sui token non eseguiti.
L'opzione CPU `--weight-scaling multiply` sostituisce soltanto la scala
del blocco W con moltiplicazione per `2**e`; `ldexp` resta il riferimento
selezionabile e il default. La conversione i16→f64 e la moltiplicazione
usano ora un solo passaggio NumPy con dtype f64 esplicito, anche con
scratch riutilizzato; non viene cambiato il dot successivo.
Tutti gli i16 simmetrici con e in [-128,128]
sono dyadic esattamente rappresentabili in binary64, senza subnormalità
o overflow. La fixture esaustiva confronta i 16.842.495 casi e il prefisso
causale ridotto; il guadagno e la parità sul workload reale vanno misurati.
`--reuse-matrix-buffer` conserva un solo scratch f64 per worker, al più
128×21.504 celle canoniche, e converte con `copyto` prima dello stesso
dot. Embedding e Norm conservano output indipendenti. Il contatore espone
il picco delle capacità trattenute; otto worker trattengono al più
176.160.768 B di scratch, da contare con KV, mapping W e resto del processo.
La verifica ridotta include code ragged e riuso seriale/parallelo;
nessun guadagno è implicito nella sola eliminazione delle allocazioni.
Il convertitore offline opzionale [C11](../../scripts/c71_pilot_convert.c)
fonde controllo del marcatore, conversione esatta e scala in un passaggio;
`--conversion-library` richiede `multiply` e host little-endian. Il dot e
gli altri operatori restano gli stessi. Il report registra il digest
della libreria; in questa modalità il tempo di validazione è compreso
in conversione, non nel contatore di lettura. Il controllo UBSan confronta
l'intero dominio legale, output causali e rifiuto del marcatore.
Il backend floating opzionale [H100 FP64](../../cuda/c71_pilot_f64.cu),
selezionato con `--cuda-library` e un worker, conserva una W i16 residente
e converte blocchi da 128 righe prima di cuBLAS DGEMV. Norm, nonlineari,
attention, KV e schedule restano CPU. Non usa BF16/TF32; l'ordine delle
somme FP64 può differire dal BLAS CPU e non implica parità bit per bit.
`profile --compare-cuda-matrices` confronta ogni dot a input identici
entro `4*K*epsilon*sum(abs(w*x))`, registra anche uguaglianza bitwise e
lavoro extra del confronto. Verificare separatamente scale osservate e
token, poi misurare senza confronto. Questi check non ammettono Γ.
Il report privato separa upload/installazione W, conversione, GEMV, D2H,
traffico nei due sensi, W host/device e workspace posseduti; contesto e
allocazioni interne della libreria richiedono ancora misura fisica.
Errori CUDA, valori non-finiti e cleanup fallito sono terminali, senza fallback.

[canonical_calibration.rs](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_calibration.rs)
esegue invece gli operatori interi: legge W packed con un buffer di al più
128 righe (5.505.024 B canonici), contato nella capacità esterna del trial.
Per le matrici legge blocchi contigui, valida tutti gli i16 e applica dot
Rust i16→i64 su slice, eliminando callback e seek per coefficiente/riga;
le somme parziali restano bounded e gli originali raw/RNE sono invariati.
Il kernel scalare resta come riferimento e lo screen lo confronta esattamente.
Gli altri operatori usano ancora la cache di riga. Il replay
conserva solo le righe A vive, raccoglie intervalli e istogrammi e mantiene
KV i16 causale. Rilascia ogni riga dopo l'ultimo consumer; trasferisce KV
al contesto successivo solo dopo tutti i 150 token e la copertura di ogni
sorgente, inclusi padding e istogrammi.
L'opzione offline `--matrix-library` del wrapper sceglie esplicitamente
`run-cuda`/`run-trace-cuda`: solo i prodotti raw interi usano l'owner e il
kernel MMA i16 esistenti. Input, output raw, RNE, altri producer, copertura
e trace restano quelli del replay; il driver C/Python indipendente non
richiama CUDA. W packed host è caricata una volta con il reader condiviso
del runner e installata immutabilmente; capacità host/device, caricamento,
trasferimenti e cleanup sono registrati separatamente. L'arena di questo
screen offline è 64 MiB, non l'arena canonica della prova. Errori non
selezionano il percorso CPU: terminano il trial e chiudono l'owner.
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
streaming. Il numero esplicito di worker del dot indipendente è 1–20;
OpenMP divide soltanto le righe, senza cambiare l’ordine delle somme i64
di ciascuna riga, e combina i marker mediante OR. Default e test locali
restano seriali; il report conserva i worker scelti e i digest C11.
Le matrici usano ora un dot C11 indipendente i16→i64 con
bound assoluto di ogni somma parziale `<2^63`, controllo del marcatore
e senza W dequantizzata; il riferimento BLAS binary64 con bound `<2^53`
resta per confronti esatti. QK e PV usano binary64 entro lo stesso bound.
RMS usa il piccolo kernel C11 indipendente
[c71_oracle_rms.c](../../scripts/c71_oracle_rms.c), con confronti esatti a
192 bit; lo stesso file ospita il dot intero, senza codice del producer Rust
o CUDA. La libreria è compilata con `-O3 -march=native` in una directory
temporanea privata e il
report registra SHA-256 di sorgente e shared object caricato.

La modalità `trace` confronta ogni frame col driver e richiede
`exact_comparison_complete:true` e `independent_oracle.complete:true` prima
di pubblicare traccia e report. I test ridotti coprono i 13 operatori,
schedulazione causale e rifiuti; l'audit del piano copre tutti i 3471 ID nei
tre contesti. Il confronto completo sui pesi reali è acquisito nel
[record di ammissione](../../benchmarks/results/c71-gamma-admission-2026-10-07-868a3e8.json),
con wall indipendente di 1.819,70 s. La validazione strutturale, il solo audit
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
  revisionate. Tempo, disco e memoria del confronto vanno nel piano
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
iniziali W/A ammette altezze 2^32/2^31, 128 colonne base e taglio Merkle
2^12. Il riferimento CPU usa quattro coset 2^20 per scan (W 1.024/A 512);
W CUDA usa gruppi di 32 coset e ring di otto colonne (128 scan). A
conserva la geometria indipendente a quattro coset e 512 ricostruzioni.
Gli stadi extension grandi hanno 12 colonne base: S1 usa coppie di coset
2^23, S2 coppie 2^21, S3 e successori
al più 2^23, sempre con taglio 2^12. Le altezze dei due profili nativi
determinano lo stadio; i test le ricavano dalla configurazione WHIR.
Il codice corrente rifiuta prima di allocazioni/sali geometrie grandi
diverse, inclusi S3 a 2^24 e i coset A che causerebbero 1.024 ricostruzioni.
La schedule è modificabile secondo il [design](design.md#risultati-attuali-e-prossime-ottimizzazioni):
prima di aggiornare i guard servono parità esatta e conto completo delle
risorse; una geometria già esclusa richiede risolverne la causa.
Il percorso corrente sostituisce il precedente rifiuto iniziale registrato nel
[checkpoint della strumentazione](../../benchmarks/results/c71-runner-measurements-local-2026-10-03-187a0b9dc9ce.json).
I sottoalberi delle query sono raggruppati fino a 1.024 righe nel riferimento
piccolo e 2^20 in tutti gli oracoli canonici grandi;
le query pubbliche restano
al più 1.024. Le stesse righe alimentano hash e aperture, ripristinando
ordine e duplicati. Il limite grande è collegato ma non eseguito: resti,
albero dei fattori e matrice restituita sono buffer contigui. Ogni livello
usa due spettri piatti; i resti discendono in due buffer contigui. La
rigenerazione conserva un solo sottoalbero e copia soltanto i path richiesti.
Fattori pubblici e rigenerazione Merkle delle aperture restano CPU;
query iniziali W/A e query extension usano l'owner comune descritto sotto.
Tutti sono conteggiati nel budget comune. Il cap delle
query iniziali dimezzato può raddoppiare i batch: nessun credito di lavoro
gratis. I punti dei claim GKR/PCS e i loro vettori rilasciano la capacità
eccedente appena aggiunti al batch, preservando ordine e MAC.

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

Le query della A originale ricostruiscono finestre byte di due
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
Il [checkpoint delle finestre](../c7.1-history/canonical-query-windows.md)
conserva il percorso CPU precedente; il
[caller residente](../c7.1-history/crypto-query-2026-10-09.md) riusa richieste,
cap e ordine, senza D2H degli originali. Costruzione pubblica dei fattori
e staging rimangono nel conto anche dopo questa integrazione.

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
documenta geometrie e lifecycle del riferimento. Il
[checkpoint residente](../c7.1-history/crypto-residual-query-2026-10-09.md)
collega queste fasi al runner misto, con parità ridotta; le shape canoniche
non sono eseguite. Per A, S1 rimane allocato sul device: il predecessore
viene interrogato e rilasciato prima della promozione dello stato successivo.
W non seleziona una retention completa.

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
l'offset packed W. L'adapter Matrix/RNE usa questo descrittore sugli handle nativi. Nel
riferimento lo scanner resta CPU; `experiment-cuda` collega producer e
scanner residenti al range ed al commitment A iniziale. Il percorso
GPU non scarica questi `Vec` come spill dello stato.
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
stream privato e un solo budget, senza spill. I 512 descrittori hanno
handle monouso, tipi, copertura inizializzata e capacità allineate a 256 B.
ABI 4 sostituisce lo slab prenotato con `cudaMalloc` per capacità viva:
`release` attende il fence e libera fisicamente il buffer. Un fold logico
conserva la capacità fino a quel release. Il callback di ammissione comune
precede ogni allocazione nativa e conta anche l'owner C++; il rilascio
scarica il conto solo dopo `cudaFree` riuscito. Una free fallita conserva
il debito ed evita di ritentare sul puntatore di proprietà incerta.
`arena_bytes` ora è la somma delle prenotazioni vive, non il cap configurato.
Le fixture piccole possono passare un callback nullo; il loader Rust
collega sempre il census comune. Il runner canonico impone il tetto
congiunto sotto; il limite locale dell'owner non autorizza arene aggiuntive.
Upload e download sono fenced; nel percorso range solo root/terminali e quattro coefficienti
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
Il percorso standalone possiede l'owner fino alla fine della prova range;
il cleanup riuscito è richiesto prima di restituire la prova. Il percorso
`Config::with_resident` prende invece lo stesso `Arc<Mutex<Runtime>>` del
produttore e un reader di finestre residenti: non crea una seconda arena
e non chiama il reader host. Libreria/device/arena/riserva devono coincidere
con l'owner originale, anche dopo modifiche alla configurazione.
Il reader riceve soltanto geometria pubblica e runtime, restituisce un
buffer originale sigillato del tipo/dimensione esatti; il consumer lo
rilascia dopo ogni finestra. Tutti i temporanei range sono rilasciati a
fine prova, senza chiudere W o sorgenti trattenute. La capacità viva deve
tornare al valore d'ingresso. Un reader fallito, errore o uscita incompleta
ferma il runtime condiviso; non seleziona CPU.
Canopy e figli condividono lo stesso buffer nativo quando cambia la vista;
H usa fold distinti, rilasciati in ordine sullo stream. Le finestre host
vengono riusate solo dopo il fence di upload. `Work.native` espone il ledger
parziale dell'owner, non una misura fisica completa. Con `native_shared:true`
è cumulativo dalla creazione dell'owner, non un delta per prova; il chiamante
deve registrare i confini di fase senza sommare ripetutamente i picchi.
Il test ridotto collega gather residente, range/GKR e PCS sui MAC originali
due volte sullo stesso owner, senza nuovo H2D delle sorgenti. Il backend
CPU di riferimento resta esplicito; `experiment-cuda` seleziona il
percorso misto, senza certificati canonici o PCS interamente residente.

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

Il [runner esplicito](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_runner.rs)
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
tempo totale. Nel backend CPU inferenza e preparazione restano fuse.
Nel backend CUDA `inference_wall_ns` misura il loop causale, inclusa
cattura KV/checkpoint/istogrammi e fence; `proof_only_wall_ns` è il resto
dell'intera risposta, inclusi allocazione/tabelle, replay, prova, attesa
verifica e journal. Non sottrae preparazione dipendente dalla risposta.
In caso di errore il runner emette su stderr `C71_RUN_METRICS` con fasi
incomplete e traffico parziale, senza valori privati; un processo ucciso
richiede comunque il log del controller. RSS/HWM sono dell'intero processo
host con entrambi i ruoli. I campioni ai confini di fase non sono picchi
per ruolo; CPU-time e HBM osservata richiedono il monitor esterno.

### Telemetria durevole del percorso crittografico

[progress.rs](../../rust/volta-pcs/src/c71_matrix/progress.rs) scrive JSONL
privato `0600`, creazione esclusiva, fsync iniziale di file/directory e di
ogni record. Il runner crea un file fratello del journal: `journals`
produce `journals.progress.jsonl`, prima della lettura di Γ. Un nuovo run
richiede nomi nuovi. Non è un journal crittografico né uno stato di resume.
Errori I/O impediscono un esito positivo; i callback PCS li propagano.
Su kill si conserva il prefisso completo e l'eventuale ultima riga troncata;
l'assenza di una fine non è un successo.

Si registrano fasi dei due ruoli, traffico applicativo cumulativo, owner
comune, sali, scansioni/accumuli, FFT, hash foglie, merge, resti e aperture.
Progressi al più ogni secondo, controllati ogni 65.536 visite/righe o per
colonna/coset; la closure lineare controlla ogni 2^20 visite e a fine round.
Wall annidati, picchi e contatori cumulativi non si sommano.
I butterfly FFT sono un censimento analitico, non istruzioni misurate.
RSS/HWM sono del processo; HBM/bus/picco fisico richiedono monitor esterno.
Nessun seed, pad, sale, W/A/KV o motivo privato nei record; pubblicare solo
la selezione revisionata. Il JSONL non è conservato interamente in RAM.

`PrivateRng` usa 4.096 B heap per sampler sequenziale, nel conto comune.
Cursore logico e cap 2^40 contano i byte richiesti; l'ultimo refill non
supera il cap. Snapshot ricrea lo stesso XOF al cursore logico senza copia
del buffer. Replay strided senza buffer; un buffer per sottoalbero
sequenziale. Sampler, dominio, ordine dei byte e separazione delle monete
rimangono invariati; nessuna Clone pubblica. Buffer, file/serializzazione
e metadata sono temporanei conteggiati, con overhead fisico nella riserva.

Lo snapshot strided corrente misura 176 B senza buffer; il buffer
sequenziale da 4.096 B è conteggiato separatamente. Le
[evidenze locali](design.md#evidenze-e-decisioni) conservano costo del
log, guard budget, stream/cap e transcript/MAC, con prova Seed6/AES
ridotta. I contatori di geometria seguono il backend: riferimento CPU
W 1.024/A 512, commitment W CUDA 128; nessun dominio D34/D35 è stato
eseguito nelle fixture locali.

### Runner CUDA sperimentale e conto simultaneo

Il runner misto usa un common owner e stream ordinato; il loader ABI4
richiede tutti i simboli PCS correnti. Tipo, identità, span, capacità,
alias, stato, W sigillato e binding dei coset precedono ogni operazione.
Assenza di simboli, launch/fence/flag, budget e cleanup falliti sono
terminali, senza fallback. Gli output restano pending fino a completamento.
Gli [stati validati e le evidenze](design.md#evidenze-e-decisioni) sono
nel design; qui sono definiti algoritmi e conto tecnico correnti.

#### Commitment W per colonne

Il ring conserva otto colonne su 32 coset, quattro valori pendenti per
foglia. Hash segue start, colonne 4,12,..116 e bande di sali contigue.
La foglia B12 da 128 valori usa 18 compressioni BLAKE3; il nodo salato
ne usa due. CV incompleto e frontier pending non sono leggibili.
Dopo copertura completa, fence/flag e ritiro sali è ammesso scaricare
soltanto digest, fino a 64 MiB per chiamata hash; il Tree iniziale importa
67.108.832 B di cache superiore complessiva e flag, senza word W.

Tile/potenze sono legati a W sigillato, Arc/layout e gruppo coset.
Un warp condivide ogni coefficiente fra 32 coset; fino a 256 prodotti
signed i16×u64 si accumulano in 128 bit, bound signed <2^87, con unica
riduzione Goldilocks prima dei pad di campo originali. La FFT in-place
riusa i cinque passaggi esistenti. Pad/ring e low/high sono distinti;
potenze di un altro gruppo o input incompleti falliscono chiuso.
Il merge strided unisce coset fratelli in ordine naturale, accettando
solo gruppi consecutivi. Con C=4096/32, frontier 2^20×7×32 =
234.881.024 B. Il ring è rilasciato prima degli output Merkle separati.

La schedule selezionata W CUDA richiede 128 scansioni analitiche sul
pinned, il riferimento CPU 1.024; A resta a 512 ricostruzioni. Le
geometrie alternative non sono simultanee e non si sommano. Device W
corrente: 3.745.182.208 B per ring/CV/potenze/twiddle/pad/frontier/sali/
tile/due flag. Con host nominato 87.195.304 B e upper replay device
785.789.696 B, envelope conservativo 4.618.167.208 B prima degli altri
owner host censiti. Non è picco fisico o ammissione canonica.
`initial_native_peak_capacity_bytes` è il massimo storico dell'owner,
non un buffer da sommare al ledger cumulativo.

#### Producer residenti e commitment A

Cinque simboli source e `cuda/c71_pcs_source.cu` collegano il sink PCS
agli originali numerici. `SourceTile`/`SourceShape` misurano 56/40 B;
kind 15/16 distinguono accumuli e conteggi pending. Una transazione fissa
da 88 B collega due buffer da 64 colonne, potenze ed istogramma opzionale.
Quattro accumulazioni modulari esatte consumano ogni byte una volta per
ricostruzione, su tutte le 128 colonne, in qualunque ordine di emissione.
Il codec riusa bias/byte plane del gather, inclusi piani i48 4+2.
Width conta byte emessi, indipendentemente da byte_first.

Producer→sink non scarica righe originali e non riceve monete PCS.
Copertura, pad originali, FFT e flag precedono la conversione a base.
C controlla span, stato e conteggio; unicità/partizione sono garantite
dalle tessere Rust dello scanner concreto. L'istogramma byte fuso nel
primo gruppo pubblica soltanto 256 conteggi privati/2.048 B senza replay
aggiuntivo. La foglia completa riusa le primitive W; il Tree importa
cache/root con controllo H foglie/H−1 nodi/128H celle e cursori sali.
Ridotti dominati dai pad possono avere H>16n; il canonico A mantiene 16n.

A conserva quattro coset, R=2^20 e 512 ricostruzioni pinned. Valori
4.294.967.296 B, frontier 301.989.888 B, twiddle 8.388.608 B, pad
1.572.864 B e banda sali 2.097.152 B; current/metadata sali aggiungono
8.388.864 B. Potenze/conteggi/flag portano l'accumulo a 4.650.965.536 B;
dopo il loro rilascio, digest/flag portano l'hash a 4.751.622.656 B.
L'accumulo usa l'upper replay device 785.789.696 B; la scansione completa
ritira i temporanei prima dell'hash, che usa solo 591.277.824 B persistenti.
Con host del componente 47.749.512 B, gli envelope nominati sono
5.484.504.744 B in accumulo e 5.390.649.992 B in hash, prima degli altri owner.
Non sono un'ammissione del percorso completo; non sommare
fasi o picchi storici. La banda host sali è eliminata. Il riferimento
CPU resta distinto; l'istogramma e le 512 ricostruzioni non cambiano.

#### XOF e capability sali

Il sampler sequenziale mantiene buffering da 4 KiB; snapshot/seek sono
al cursore logico, senza copiare il prefetch nel replay strided.
`PrivateRng::salts4` legge solo candidati mancanti, filtra in ordine e
preserva rejection/cap/seek; il batch è selezionato nei soli snapshot
strided perché il sequenziale già bufferizzato peggiora nel confronto
locale. La decisione e le misure sono nelle evidenze Tree A.

Il sampler GPU mantiene dominio di 34 B incluso NUL, seed di 32 B/input di 66 B,
descriptor di 112 B, XOF a 16 word LE, rejection Goldilocks e cap 2^40.
Prefix/mask bounded fino a 2^24 candidati conserva il cursore subito dopo
il quarto accettato, anche oltre 2^32. L'owner compatta descriptor,
progress, flag e counter in 168 B, allineati a 256 B. Scratch prescan massimo
10.519.552 B; con starts/offsets/metadata, 27.297.024 B W o 23.102.720 B A.
Scratch ed offsets device sono ritirati dopo fence prima del ring;
current e metadata rimangono nel conto delle fasi hash.

Sei simboli sali obbligatori creano una capability `PrivateSalts` opaca,
non clonabile e owner-bound. Kind17 non ammette allocazione, lettura,
upload o rilascio pubblico. Seed e puntatori arrivano solo al consumer
PCS, mai al producer numerico o alla telemetria. `with_private_rng`
parte dal cursore logico corrente; `advance_to` invalida il prefetch ed
avanza una sola volta dopo prescan riuscito, conservando stream/cap.
Replay/hash condividono il flag sticky, una verifica/fence per gruppo,
nessun H2D sali o fence per banda. Current finale e byte consumati devono
coincidere col prescan; digest negati fino al ritiro privato. Il flag è
rilasciato dopo fence valido senza ripeterlo; free-failure resta terminale.
Owner host 37.288 B al checkpoint sali e Stats 152 B; la API Rust sali
aggiunge 48 B. Il successivo owner lineare aggiunge 120 B host permanenti,
da contare anche nelle altre fasi, senza modificare i record precedenti.

Il lavoro XOF logico prescan+replay resta almeno 256/128 GiB W/A; gli
upload sali host 128/64 GiB sono sostituiti da 168 B H2D metadata per
commitment. Il D2H di controllo minimo è 25.211.904/20.998.144 B, inclusi
starts/offsets/current e 44 B per chunk/8 B per gruppo; rejection può
aggiungere chunk. Sono conti analitici, non tempi o traffico fisico GPU.
Il driver prescan sequenziale non verifica la gerarchia CUDA.

#### Aperture e FFT naturale

Le aperture CPU dividono direttamente per divisori monici di grado ≤8,
evitando shift separato dei pad quando il messaggio entra in un batch.
Mantengono base/Fp3 e byte di prova, senza cache di righe in produzione.
Le prove composte ridotte usano 16 MiB di righe iniziali nel riferimento
solo della fixture, col budget attivo; getter reali sono verificati
separatamente. D15 W/A uncached e CPU lookup/GKR/WHIR superano 60 s locali:
restano esiti negativi, non credito di completamento.

La [FFT naturale](../c7.1-history/crypto-transform-2026-10-09.md) è una
primitiva sul common owner; il successivo
[checkpoint query](../c7.1-history/crypto-query-2026-10-09.md) collega il caller A iniziale.
`c71_pcs_transform_twiddles`, `c71_pcs_transform` e `c71_pcs_read_words`
sono tre simboli ABI4 obbligatori, +24 B nella API Rust; nessun nuovo
owner/buffer permanente. Log N da 1 a 24, batch≤2^20, word complessive≤2^28.
Valori/scratch base completi e twiddle sono distinti, con binding di
lunghezza/orientamento. Ordine naturale, inverse normalizzata una sola
volta per 1/N; geometria dispari log>1 ricompone nello scratch e copia
l'intero buffer D2D, addebitato anche prima di un successivo errore.

Il segmento batch≤32.767 mantiene le due metà dispari entro grid.z≤65.535
([limiti NVIDIA](https://docs.nvidia.com/cuda/cuda-programming-guide/05-appendices/compute-capabilities.html)).
Shared massimo per riga 32.768 B, transpose 16.896 B. La lettura esplicita
base è bounded a 2^20 word/8 MiB, controlla canonicità e nega fasi sali
private. Per q=2^20, valori/scratch/due twiddle di 2q richiedono 67.108.864 B;
sono esclusi fattori, finestra originale, low/high, pad, output host,
Tree/replay e altri owner. Non è l'ammissione della query completa.
PCS v³=v+1 e MAC u³=2 rimangono distinti; la trasformazione base non
reinterpreta le componenti d'estensione. Il caller extension usa tre
componenti base separate; le query iniziali W ora usano lo stesso owner e le
ricostruzioni originali A non aumentano.

`c71_pcs_query_weight_low` è il quinto simbolo query iniziale obbligatorio,
+8 B di API Rust. Legge W packed sigillata tramite la stessa mappa, controlla
il prefisso vivo prima dell'indirizzo e mantiene padding/pad e ordine delle
query. Nessuna finestra degli originali W, flag gather o scratch aggiuntivo:
un launch per blocco, 256 thread, grid≤4096, shared zero. Il subtotal device
al cap è 857.338.880 B, mappa allineata 126.464 B inclusa; matrice finale host
1 GiB e colonna 8 MiB restano separate. Fattori pubblici, path e rigenerazione
Merkle delle aperture sono CPU. Il
[record locale](../../benchmarks/results/c71-crypto-w-query-profile-local-2026-10-09-e55e1a7b4ad0.json)
confronta 18 casi Horner e full wire/FS/RNG/MAC D10 con getter host vietati;
non misura CUDA o il caso pinned completo.

512 query WHIR richiedono tutti i 4096 record di ciascun sottoalbero
Merkle distinto: batch≤256 sottoalberi, q_eff≤2^20, fino a due batch.
Non sono soltanto 512 valutazioni dirette. Al cap, W ha 29.390 blocchi
root per batch, ciascuno con 33 launch remainder e 64 MiB di packing D2D
delle quattro FFT dispari; gli altri accessi HBM restano aggiuntivi.
La costruzione pubblica conta 19.922.807 DFT e 679.477.284 celle trasformate,
non istruzioni o tempo. Questi costi residui sono nel profilo di sorgente.

Il reader `NativeQuery` collega le finestre originali al medesimo owner
numerico. Resti high-to-low, shift dei pad e discesa dell'albero usano
FFT base dirette/inverse e quattro API ABI4 obbligatorie:
`c71_pcs_query_low`, `c71_pcs_query_remainder`, `c71_pcs_query_shift`,
`c71_pcs_query_add` (+32 B nella API Rust). I fattori pubblici, reciproci
e shift sono costruiti CPU e caricati; i pad rimangono privati al consumer.
Il reader riceve soltanto runtime e intervallo pubblico originale, senza
monete PCS. Restituisce byte residenti sigillati; errore, owner/tipo/span
diverso o stato pending fermano la prova. Nessun getter o reader host
sostitutivo. D2H contiene solo le colonne della matrice restituita e i
flag di controllo già esistenti, mai i byte originali. Ordine/duplicati
e tutti gli endpoint MAC rimangono quelli del riferimento.

Per q=2^20 e 128 colonne, il subtotal device query è 1.125.647.872 B:
fattori 704.643.072, twiddle allineati di tutti i livelli 67.110.400,
shift opzionale 16.777.216, low/pad/resti/work/scratch 67.108.864,
pad originali 1.572.864 e finestra byte 268.435.456 B. Si aggiunge un
flag gather allineato da 256 B. Host: matrice finale 1.073.741.824 B e
staging di una colonna 8.388.608 B. Il massimo H2D nominato per batch è
722.993.152 B, D2H della matrice 1.073.741.824 B più 4 B per ogni flag
finestra. Sono subtotal analitici, **non un'ammissione congiunta**:
costruzione dei prodotti pubblici, conversioni/cache DFT CPU, Tree/replay,
righe/sali/path già aperti, numerica, PCG/maschere, prove/codec, entrambi
i ruoli e riserva fisica rimangono aggiuntivi. I temporanei native-query
sono ritirati prima di rigenerare/copiare le righe del batch corrente;
le righe dei batch precedenti rimangono vive. La retention S1 inizia solo
dopo apertura/rilascio del predecessore A, quindi non coesiste con questo
scratch. Questi lifetime non liberano implicitamente snapshot o cache.

La parità contro Horner verifica richieste di finestre identiche al
riferimento; il commitment iniziale A conserva 512 ricostruzioni.
La catena D10 uncached del checkpoint query iniziale verifica wire,
FS/RNG, MAC originali e due verificatori, con commitment iniziale ed
extension CPU a quella sorgente storica.
Tempi Rust O0/C++ O2 non consentono rapporti di speedup o stime H100.

#### PCS residuale e query extension residenti

`ReplayModel::make_sourcewise_backend` collega `native_residual` a
`model.native_original` nella produzione e nelle fixture della catena.
`c71_pcs_residual.cu` esegue singleton, contributi originali/residenti,
coset, OOD, retention e fold nella base PCS v³=v+1; `c71_pcs_residual_query.cu`
carica i blocchi delle query extension. Sono obbligatori 19 nuovi simboli
ABI4: nove residuali, quattro di contrazione, cinque Query E ed uno
hash paired privato (+152 B nella API Rust). La loro assenza è terminale.
Owner, stream ed allocatore sono quelli numerici originali.

Shape/Chunk/E sono 32/16/24 B. Il packet EQ usa chunk di al più otto bit,
cinque descrittori e 1.280 celle; conserva ordine MSB, punti zero/uno ed
il supporto completo dopo ogni fold. La sorgente A usa il codec biased
originale, compreso lo split i48; W usa signed Goldilocks e lo stesso
mapping packed sigillato. Ogni scan produce insieme le tre componenti:
nessun download per riga o replay originale separato per limb.
La riduzione singleton ammette il primo fold canonico da uno a sette bit
in 128 bucket; le geometrie Flat maggiori non hanno fallback nativo.
OOD mantiene i pad dopo la lunghezza completa, con lookup di potenze
pubbliche spezzato. Contrazioni bounded riusano EQ e covettori originali,
restituendo soltanto gli scalari E finali.

Il ring extension contiene quattro colonne E, tre limb per colonna e
due coset: `((colE*3+limb)*2+lane)*R+row`, cioè 24R word. L'owner applica
pad e 24 FFT seriali, controlla flag/fence e ritira lo scratch prima del
seal. Le foglie mantengono dominio 32 B, valori 96 B e sali 32 B: tre
compressioni BLAKE3, con l'ultimo blocco da 32 B. La prima lane scrive R
foglie; la seconda calcola i nodi fratelli in-place, in ordine originale.
Bande senza attraversamento di lane e progresso logico 2R precedono il
seal dei R nodi. A R=2^23 l'output hash richiede 268.435.456 B, 256 MiB
in meno rispetto a 2R digest separati. Frontier, cursori, ring e sampler
rimangono simultanei nelle rispettive fasi. Sali group2/R23 conservano
dominio, stream, seek, rejection e cap 2^40; i guard iniziali group4/32
e le geometrie escluse rimangono invariati.

A crea tre plane SoA soltanto dopo apertura e rilascio dell'oracolo
iniziale. Il successore può essere committato mentre il predecessore è
apribile; la promozione richiede poi il rilascio di quest'ultimo. I fold
virtuali di zero, uno o due bit leggono le stesse plane immutabili.
Tipo privato, generazione e posizione di ciascun limb sono sigillati:
scambiare c1/c2 o usare una generazione diversa è terminale. W non crea
una retention completa. I limiti di memoria contano anche old+new durante
la promozione; nessuna copia host di S1 è autorizzata come spill.

Query E usa colonne di n=2^(remaining−2), capacità power-of-two q≤2^20,
pad originali e blocchi discendenti. Un caricamento produce `low[limb*q+i]`
per tutti i tre limb; i resti base esistenti sono riusati con token,
limb e grado sigillati. A legge le plane trattenute con prefisso virtuale
≤2 e non richiama il producer originale. W parallelizza 32 coefficienti
su blocchi di 256 prefissi, con otto worker per coefficiente, riduzioni
modulari esatte e CAS Goldilocks; indice/live precedono ogni lettura W.
Shared è 12.288 B/CTA, grid≤8.192 con stride, task≤2^25; nessun nuovo
buffer globale oltre a low3. Il loader tenta un launch per init/pad e
un secondo soltanto quando ci sono contributi W. Letture, upload,
rilascio generico e mutazioni del remainder sono vietati durante la query.
Finish legge tre colonne e un flag, controlla canonicità e ritira il
packet/low/flag prima della pubblicazione. Solo la matrice finale passa
al Tree, che mantiene autenticazione Merkle e endpoint MAC originali.

Per q=2^20, il subtotal device Query E è 864.028.160 B: fattori
704.643.072, twiddle allineati 67.110.400, low3 25.165.824, quattro resti
33.554.432 e work/scratch 33.554.432 B; packet EQ/pad e flag si aggiungono.
Host contemporaneo di pubblicazione: matrice 96q, colonna Rust 24q e
staging C++ 24q, in totale 144q (150.994.944 B al cap). Fattori pubblici
in costruzione, cache DFT, righe/sali/path dei batch precedenti ed altri
owner sono ulteriori. Query scratch si ritira prima della rigenerazione
del batch corrente. A S1 usa 3.221.225.472 B di plane; la promozione a
due fold può far coesistere 4.026.531.840 B old+new. Il layout host
del nuovo owner è verificato a 42.088 B; dimensione e capacità sono nel
[record del checkpoint](../../benchmarks/results/c71-crypto-residual-query-local-2026-10-09-9a5da712a258.json), senza credito di picco fisico.

Le parità ridotte, i benchmark host, il confronto WHIR A/W ed i failure
sono raccolti nella [storia](../c7.1-history/crypto-residual-query-2026-10-09.md).
Il commitment iniziale A conserva 512 ricostruzioni; scansioni S1,
contrazioni e query hanno contatori distinti. Nessun tempo host o subtotal
qui dimostra il completamento D34/D35, il target 65 s o la parità CUDA.

#### Closure e candidate aritmetiche

La closure lineare seleziona una scan originale per round, D·live visite,
senza getter del suffisso zero. EQ del prefisso usa chunk ≤8 bit/256
celle; Cube residuali ordinati per ampiezza/intervallo prendono i punti
in prestito. Nessuna divisione, bitmap o array D34/D35; sfide 0/1,
sovrapposizioni e ordine arbitrario conservano coefficienti/endpoint.
Unicità è precondizione dello scanner; il confine controlla live/range/
count ed errori prima delle tre correlazioni. Wire/FS/MAC e riserva 3D+2
restano invariati; capacità/realloc/forme pubbliche sono nel budget.
Il [checkpoint lineare](../c7.1-history/crypto-linear-2026-10-09.md) collega
`native_original` A/W allo stesso owner. Quattro simboli ABI4 obbligatori
gestiscono packet canonico, accumuli e risultato; kind18 privato non è
allocabile, leggibile o rilasciabile genericamente. Begin fa una fence
sugli upload prima di liberare il packet host; finish restituisce cinque
Fp3 MAC e flag, valida e ritira i tre buffer prima della pubblicazione.
Sono 124 B D2H e due fence del consumer per round: sul pinned 34 scan A
e 35 W, rispettivamente 4.216/4.340 B di risultati. Producer, mapping,
flag e sincronizzazioni propri restano ulteriori. W carica il mapping
sigillato una volta per prova; A chiama lo scanner senza lock esterno.

Shape/Chunk/Group/Interval/Result sono 32/16/16/64/120 B. Il cap owner
packet è 1 GiB, con al più 2^20 intervalli e 2^25 punti: upper nominato
allineato packet+output+flag 872.447.744 B. Il caller `MAX_CUBES=2^19`
ammette al più 17.825.792 punti residuali; il corrispondente upper
conservativo è 461.405.952 B. Sono esclusi forme originali, descrittori
temporanei, staging host, producer/Tree/PCG/prova e margini; il census
conta capacità/realloc e ogni prenotazione. Telemetria riporta capacità
host effettiva e bound temporaneo per round, delta completo del common
owner compresi producer/mapping, senza sommare picchi cumulativi.
Owner host al checkpoint lineare 37.408 B, Stats 152 B, API Rust +32 B; kernel 256
thread, grid ≤8192 e shared 30.720 B. Registri/spill/scheduling e conto
fisico restano da misurare. Nessuna ammissione congiunta segue da questi
subtotal. I 16 casi codec/endpoints, 30 rifiuti, quattro simboli mancanti
e cinque fault di avanzamento preservano le tre correlazioni per round;
la catena D10 signed W verifica full wire/FS/punto/MAC originale con PCS
CPU. La parità A completa e quella CUDA non sono implicite in tale catena.

La [candidata Tensor W](../../cuda/c71_pcs_weight_tensor.cu) usa quattro
limb16 biased, dot INT8 pack/compose esatto e correzione 32768·sum_W:
somma signed <2^87, shared 8.448 B, nessun nuovo buffer globale.
Il digit aritmetico −32768 è legale nella decomposizione, mentre il
marcatore negli originali W resta vietato. `c71_pcs_weight_tensor` riusa
ammissioni, W sigillato, FFT e flag dell'ordinario. Il confronto
`c71_pcs_compare_words` verifica tutte le word canoniche di due buffer
base completi distinti, senza download campi, solo 4 B di flag. Entrambi
sono obbligatori ABI4; la selezione canonica resta ordinaria.
Il diagnostico Q256/R64 con W sintetica da 4 MiB è compilato solo come unità
host, non linkato/eseguito: non misura throughput pinned.

Le [candidate QK/PV MMA](../../cuda/c71_attention_mma.cu) mantengono
originali i16/PiQ14, raw i64 e RNE. QK usa N8 interamente nel prefisso
comune M16, poi dot scalari causali; PV usa K32 comune e tail per output
≤46. Per M16: ≤232 dot QK scalari e ≤616 prodotti PV per lane. Anche
future già inizializzate non vengono lette. Nessuno staging/shared
aggiuntivo; array interi nominali 124 B/thread più raw 8 B. Registri/spill,
compilazione e prestazioni CUDA rimangono da verificare. Entrambe le
candidate restano non selezionate; parità fragment/shuffle/i128 host
non prova kernel o scheduling GPU.

La CLI seleziona soltanto `reference-cpu` oppure `experiment-cuda`; la
seconda aggiunge `LIBRARY DEVICE` agli stessi cinque argomenti di input.
Richiede `c71-seed6-reference`, PCG reale AES e libreria ABI 4 con tutti i
simboli aggiornati. Nessun fallback se libreria, GPU, simboli o fence
falliscono. `PREPARATION_BYTES` è fra 1 GiB e 6.174.015.488 B, non un limite
del processo. Lo scanner nativo usa righe fino all'ultimo consumer, batch
derivati dalle shape (anche 149 righe della Norm finale), padding pubblico
e conteggi originali. La copertura completa precede il seal di ogni finestra.

| Owner/fase simultanea | Capacità o payload e collocazione |
|---|---|
| W immutabile esclusa | 61.394.690.560 B host e device; la stessa Arc host resta viva fino al teardown del budget |
| Contatore comune | Ogni layout Rust, incluse capacità/reallocazioni dei due ruoli, più owner C++ e prenotazioni CUDA allineate; picco aggiornato all'allocazione, non solo ai confini di fase |
| Massimo congiunto ammesso | 5.905.580.032 B di allocazioni; allocazioni oltre il tetto falliscono prima della prenotazione |
| Riserva fisica esplicita | 268.435.456 B per allocator/mapping, capacità libere trattenute, stack, socket, driver/runtime CUDA e stack kernel; sufficienza ancora da misurare |
| Massimo analitico condizionato | 6.174.015.488 B = tetto allocazioni + riserva; margine 268.435.456 B sul contratto |
| Stato device persistente | KV450 405.504.000 B + checkpoint 98.380.800 B + 121 istogrammi allineati 63.438.848 B + tabelle allineate 23.954.176 B = 591.277.824 B |
| Replay device | Upper derivato da porte, batch e ultimi consumer: 785.789.696 B **incluso** lo stato persistente, copie KV e istogrammi duplicati; niente somma di massimi separati |
| PCS iniziale CPU/A | Quattro coset 2^20×128×8 = 4.294.967.296 B insieme, inclusi quelli in attesa; frontier W riferimento/A 402.653.184 / 369.098.752 B, cursori sali 8.388.608 B; FFT, radici, pad, potenze e stato device restano conteggiati |
| PCS iniziale W CUDA | Ring otto colonne/32 coset 2.147.483.648 B, CV 1.073.741.824 B e frontier 234.881.024 B; subtotal device del componente 3.745.182.208 B con sampler privato, senza sommare la schedule CPU alternativa |
| PCS S1/S2 | Ring nativo S1: due coset 2^23×12×8; S2: due coset 2^21×12×8 con plane S1 A da 3.221.225.472 B vive. Promozione soltanto dopo rilascio del predecessore; old+new delle plane conta fino al retirement |
| Aperture PCS | Matrice contigua; query iniziali W/A ed extension native con subtotal e lifetime sopra, fattori pubblici e rigenerazione Merkle CPU. q≤2^20; righe/sali/path precedentemente aperti restano conteggiati |
| Closure lineare | Packet/output/flag nativi e staging host sopra; forme pubbliche e producer rimangono nel conto. Una scan originale per round, mapping W una volta; nessuna retention implicita |
| Range/staging | Range A ≤1 GiB device; finestra originale query A ≤256 MiB device, senza copia byte host nel caller nativo (≤256 MiB host nel riferimento CPU); W staging signed ≤256 MiB, padding pubblico signed host ≤55.574.528 B; ogni copia rimane nel conto |
| GKR, Seed6 e altro host | Compact RMS, EXP30/lookup, contrazioni, MAC originali, Seed6 reale dei due ruoli, tabelle/profili, certificati/codec e metadati passano dallo stesso allocatore; nessuno slot figurativo li rende gratuiti |

Il conto per fasi distingue backend legacy e percorso nativo, con lifetime
di query, S1 e cache iniziali A1..A3; il
[record del checkpoint](../../benchmarks/results/c71-crypto-residual-query-local-2026-10-09-9a5da712a258.json) lega il backend `s1-prepared`
alle shape correnti di tutti gli stadi extension nativi. È uno screen
nominato con `joint_admitted:false`, non un
conto completo. Il [conto aggiornato](../../benchmarks/results/c71-crypto-resource-inventory-local-2026-10-09-b19822b8a3fb.json)
enumera 460 fasi: A3 accumulo è 5.744.879.732 B, A3 hash 5.595.450.452 B;
S2 A3 query publication, Writer incluso, è 5.642.161.460 B. I subtotal
precedono le ulteriori capacità. Hash, W e consumer delle plane trattenute
usano stato numerico persistente; replay e padding host esistono nelle
scansioni originali A. Nessuna ricostruzione è aggiunta.
Le 11 classi dell'inventario sono esplicite:
layout/Arc/metadati e tabelle pubbliche, costruzione/conversioni/cache DFT
dei fattori query, batch già aperti, PCG/VOLE/journal di entrambi i ruoli,
prove/codec/framing e realloc, GKR/range/numerica fuori dall'envelope,
EQ/PowerBlocks e bande di contrazione host, forme/endpoint/marshalling,
metadata/flag/workspace degli altri consumer, temporanei finali bounded
e nuove cache/pad del base case. Non sostituirle con uno
slot fisso o un residuo gratuito. Sette classi hanno formule dei payload
principali; restano quattro chiusure tipate: sei profili/metadati,
body/decoder/proof, costruzione delle forme prima dello shrink/bind e
wrapper/telemetria. Il
[ledger eseguibile](../../scripts/c71_temporary_ledger.py) conserva il
percorso legacy e la sua provenienza; i vecchi record non cambiano. Il
[record dei lifetime](../../benchmarks/results/c71-crypto-retirement-local-2026-10-09-96b69ded52c1.json)
lega il rilascio di batch W e prova W prima delle chiusure A, e di batch/prova
A dopo la chiusura corrente: ordine FS/wire/MAC invariato. Il cap codec dei
claim W di 470.351.872 B è un upper analitico, non una capacità misurata.
La vecchia voce certificate=128 MiB non è un bound provato. Writer canonico
ora prealloca esattamente 96 MiB, senza crescita/realloc dopo begin;
body temporanei, proof e decoder richiedono ancora il proprio conto.
I subtotal nominati servono a controllare le dimensioni; non sono
picchi canonici misurati né una prova di completamento. L'autorità sul
massimo delle allocazioni è [census.rs](../../rust/volta-pcs/src/c71_matrix/census.rs),
con callback dall'owner CUDA: copre anche costi non nominati nella tabella.
Non sommare due volte stato device, root, picchi o contatori cumulativi.

La policy Linux/glibc fissa la soglia mmap a 128 KiB e al più due arene,
impedendo l'aumento adattivo della soglia dopo le FFT. Una prova locale
controlla il ritorno della prenotazione mmap di uno scratch da 16 MiB.
La contabilità dei layout non misura stack, arrotondamenti fisici o contesto
CUDA: questi devono entrare nella riserva dichiarata. Per questo
`physical_runtime_allowance_verified:false` e `complete_physical_peak:false`
restano corretti; il controllo H100 richiede anche zero rifiuti di budget,
completamento verificato e margine fisico, non soltanto un contatore basso.

`c71_original_read` permette staging bounded soltanto di prefissi già
inizializzati, controlla tipo/span, contabilizza D2H e sincronizza prima
del consumo. Il gather accetta viste nei prefissi KV, non celle future.
Questi byte non passano al verificatore. Il range A resta residente;
La finestra range A del runner scende da 2 GiB a 1 GiB: cambia il numero
di finestre, non gli originali né la geometria del range.
I commitment iniziali W/A, le query iniziali W/A, gli accumuli lineari,
PCS extension FFT/Merkle/sali, contrazioni e query extension sono residenti.
Fattori pubblici, Merkle delle aperture, GKR non-range, MAC, PCG, codec e verifica
restano CPU dichiarati, non fallback impliciti. La rigenerazione di una
generazione storica rilascia quella precedente e riusa KV450 originale;
una copia D2D della sola slice corrente serve quando un consumer ordinario
richiede KV come matrice. Tutte le copie sono addebitate.

Il test locale della schedule copre 150 token e tutti i 13 tipi nei tre
contesti senza caricare W; il test numerico dello scanner è ridotto.
Non è una prova completa, né una misura D34/D35 o H100. Il primo esperimento
deve misurare anche gli eventuali superamenti dei target, non nasconderli.
Il [checkpoint precedente](../../benchmarks/results/c71-device-runner-local-2026-10-04-1ec6720bb494.json)
resta immutabile e conserva la violazione da 10.737.418.240 B. Il codice
corrente la rimuove mediante rilascio fisico e frontier più piccole. I
61 checkpoint restano una sola generazione. Il raggruppamento mantiene
512 ricostruzioni A, pagando quattro accumulazioni iniziali per coefficiente;
S1 e S2 ne pagano due. Il conto del lavoro deve includerle: nessun trasferimento
a setup globale, nessun credito automatico ai tempi precedenti.

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
Il ledger ABI 4 (152 B) separa W e arena, somma le prenotazioni nel picco
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
Il loader controlla ABI 4 prima di creare un contesto e richiede i simboli
di vista/abort; la precedente ABI 2 da 144 B è rifiutata prima di leggere
il nuovo ledger, che aggiunge `d2d_bytes`.
`produce_native` collega tutti i 13 tipi di producer, riusando i dispatcher
di base e nonlineare e le route Norm/QK/softmax/PV. Verifica arità, presenza
esatta di coda/istogramma e assenza di token estranei all'embedding;
il binding da solo non è un preparatore completo. Il runner
`canonical_device` lo collega a scanner/replay GPU, senza fallback.
`NonlinearTables` valida e carica tabelle i16, 60 EXP30 i32 e due finestre RoPE alle
posizioni assolute del contesto: 23.954.072 B logici, 23.954.176 B allineati
nella stessa arena. Il packing host temporaneo è ancora addebitabile,
oltre alle tabelle pubbliche originali; non è spill privato. Layout,
ricette, posizione e sorgente/righe dell'input sono controllati a ogni
operazione. Ogni istogramma usa 524.280 B logici / 524.288 B riservati e
una bitmap Rust di 150 B (50 per softcap, 8.192 per EXP30); non è consumabile dal gather
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
il conto completo. L'owner dispone ora di 512 descrittori fissi, conteggiati
in `host_owner_bytes`; l'esaurimento resta terminale. La schedule deve
ancora censire tutti gli istogrammi, checkpoint e workspace simultanei.
RMS conserva prodotto ponderato opzionale, somma dei quadrati per testa e
output i16. Usa gli stessi tre coefficienti u128 di `rms::Integer`, con
envelope verificato prima del launch e confronto delle soglie quadrate
senza floating point. La riduzione shared usa 2.048 B per CTA.
QK/PV sono kernel scalari interi, non MMA: la loro prestazione va misurata.
QK produce zero sui key futuri senza leggerli; PV legge solo il prefisso
causale e le 32 Pi originali. `Tail` controlla sorgente/layout/ricette,
predecessore completo e append consecutivo. Una sola capacità i16 per
450 token è condivisa dai tre prefissi; il passaggio di contesto non copia
né rialloca KV. L'append copia soltanto le nuove righe D2D e fa fence
prima di estendere il prefisso. `c71_signed_append_at` confronta anche il
prefisso device con l'offset atteso: una seconda continuazione dello stesso
prefisso fallisce prima della copia, non sovrascrive né accoda fuori posto.
Il loader richiede questo nuovo simbolo, rifiutando le librerie precedenti
che espongono soltanto l'append senza offset. I prefissi storici rimangono
leggibili con la propria maschera causale anche dopo il completamento
del terzo. L'ultimo descrittore condiviso rilascia il buffer; ogni condivisione
e rilascio verifica l'owner Rust. Il runner lega ora la creazione
della continuazione alle sole accettazioni durevoli.
EXP30 verifica score futuri zero, tabella E(0)=2^30 e range, accumula Z
esatto e arrotonda Pi Q14 con pareggi al pari. La riduzione shared usa
3.072 B per CTA. I 32×106 query di padding aggiungono pubblicamente
`32*106*(O+150)` visite al bin zero una volta, con 8 B H2D e fence;
le righe vive completano l'istogramma senza doppio conteggio. Il marcatore
−32768 resta vietato agli input aritmetici. I test ponderati RMS usano W
ridotta, non installano i 61 GB canonici; la parità delle route canoniche
copre Norm non ponderate e le due famiglie attention nei tre contesti.
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
Il rilascio anticipato ritira e libera fisicamente anche il flag dopo fence. La
copertura del layout è responsabilità del wrapper Rust fidato; l'ABI C
controlla codec, accessi e stato del buffer, non certifica il DAG da sola.
Il loader richiede anche i tre simboli begin/scatter/seal. Il gather è
collegato al replay e al range sul lifecycle comune del runner; i consumer
PCS ancora CPU ricevono staging bounded esplicito. Il ledger C non
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
Il loader ABI 4 richiede anche `c71_dense_pointwise`.
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
runtime e tempi restano nel conto globale da misurare. Il chiamante
del runner fornisce gli ID dello snapshot causale fissato; l'adapter
non prova da solo quella provenienza. Il loader richiede anche il simbolo
embedding. Questo binding software non sostituisce la parità hardware.
Il codec byte condiviso accetta l'intero intervallo signed della propria
larghezza, incluso −32768 per `U/global/argmax_slack`: la prima versione
del gather rifiutava erroneamente questa cella valida. Il rifiuto del
marcatore resta nei confini aritmetici e nell'upload signed ordinario;
il producer argmax residente produce quello slack senza upload signed.
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
Il [profilo del caller](../../scripts/c71_residual_profile.py) riusa il ledger
legato all'ammissione Γ e verifica la selezione `prove_sourcewise(true,None)`.
159 programmi, profondità massima 99 e 347.937.024 celle vive implicano per
risposta 998.927.195.904 callback del checkpoint, 4,85×10^16 valutazioni
Booleane di replay e 9,72×10^14 moltiplicazioni Fp3 del core dopo pruning.
Sono sottoconti di sorgente, senza tempo/credito GPU; i callback non sono
nuove ricostruzioni A. L'endpoint byte resta sourcewise CPU. Non c'è un
consumer RMS nativo già selezionato; il target 65 s resta strutturalmente
aperto. Concedere quattro round gratuiti al sintetico a scale zero non
lo rende fattibile e non sostituisce questo conto sul Γ corrente.

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

Lo [stato H100](runpod-tests.md#stato-e-sequenza-operativa) distingue
parità ridotte PASS, Γ ammesso dopo due replay e confronto indipendente
completi, e prova canonica ancora da verificare. Il mapping W readonly è
materiale globale immutabile; non sottrarre la lunghezza del packed dal
RSS senza misurarne la residenza. Nessun campione offline chiude l'arena
canonica o tutte le capacità trattenute.

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
| Temporanei, allocazioni congiunte host/device | ≤5.905.580.032 B imposti dal codice |
| Runtime/allocator/stack non misurati dai layout | 268.435.456 B espliciti, da verificare fisicamente |
| Massimo ammesso con riserva / margine | 6.174.015.488 / 268.435.456 B |
| W device + massimo con riserva (upper conservativo) | 67.568.706.048 B; attribuisce conservativamente al device anche i byte host |
| Tempo e lavoro | Nessun nuovo upper completo: i tempi dei vecchi screen non incorporano questa implementazione |

I picchi e i tempi degli screen precedenti appartengono a primitive e
premesse diverse, conservate nei record storici. Non sono upper applicabili
al runner misto corrente. KV e tabelle sono già nel conto temporaneo,
mai aggiunti una seconda volta al picco CUDA.

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

Il conto simultaneo deve comprendere workspace numerici e DFT, hash,
spettri, copie, stato PCG/OT/Fp6, runtime e allocator. Il census addebita
le allocazioni effettive; il picco fisico completo resta aperto e un
costo ignoto non vale zero. Γ pinned è ammesso; dopo ogni ottimizzazione
riconciliare il nuovo ledger dei tre contesti con `c71_calibrate.py ledger`
e con il budget comune, senza ereditare tempi o picchi precedenti.
Il benchmark della prova richiede anche integrazione canonica, input,
SHA pulita, durata autorizzata, arresto e soglie dichiarate in
[runpod-tests](runpod-tests.md), senza requisito di preventivo economico.

Il verificatore usa al massimo quattro worker complessivi, senza pool
annidati che moltiplichino i thread. Si contano decoding, hash, campo,
GKR/PCS, PCG, MAC e aggiornamento dello stato; registrare tempo CPU e
wall, RSS, affinità e backend AES. Non richiede W, una GPU o un servizio
remoto. Tempi di CPU differenti non sono intercambiabili.

Il replay offline può prendere in prestito le righe originali KV i16 per
QK/PV, con limite causale verificato a ogni riga, marker rifiutati e
workspace contato nel picco del bundle entrante. Gli output interi e
l'ordine delle somme per output restano quelli del produttore originale;
le letture logiche mantengono lo stesso censimento. Non cambia il runner
della prova. Lo screen `profile-attention` confronta entrambi i percorsi;
solo il confronto indipendente completo può chiudere il trial reale.
