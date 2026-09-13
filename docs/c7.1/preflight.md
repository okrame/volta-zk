# C7.1 — preflight locale, 2026-09-13

**NO-GO per H100.** La FFT a blocchi ora compila per `sm_90` e supera i
controlli CPU ridotti. Il replay completo dei primi oracoli W/A/vecchie A
è però escluso nelle condizioni esplicite sotto. La variante con apertura
per resti polinomiali riduce questo lavoro; non è ancora una costruzione
integrata ammessa. Nessun pod, spesa o esecuzione GPU è stato effettuato.

I conti riproducibili sono in
[`integrated_resource_ledger`](../../scripts/c71_streaming_screen.py) e
[`c71_query_remainder.py`](../../scripts/c71_query_remainder.py), `credit:false`.
`null` significa ignoto; il corrispondente upper di ammissione è **+infinito**.
Non è possibile dare un upper completo finito usando soltanto un picco di
banda e componenti ancora privi di implementazione e contratti temporali.

## Lower di banda e calcolo separati

Per uno stadio k, `max(B_k/BW_max,I_k/R_max)` è un lower. Sommare i lower
solo tra stadi distinti obbligatori; non sommare IO e calcolo dello stesso
kernel come se fossero seriali. Un upper richiede invece limiti al lavoro,
throughput **minimi garantiti per quel carico** e attese massime; non si
ottiene invertendo picchi, medie o percentili.

Il riferimento [H100 SXM](https://www.nvidia.com/en-us/data-center/h100/)
ha 80 GB e 3,35 TB/s nominali. Lo screen condizionato usa `BW<=3,35e12 B/s`,
allocazioni senza compressione e credito cache **<=256 MiB per traversata**.
Per una sorgente packed di S byte, Q coset da 4 GiB e cinque passaggi
FFT separati, prima di hash/sali/ricostruzione:

```
HBM_lower(S,Q) = Q * [(S - 256 MiB) + 10 * (4 GiB - 256 MiB)]
```

La sola FFT globale letterale a 22 passaggi richiedeva >=54,155 s per
encoding W; resta scartata. La FFT a cinque passaggi riduce questo costo,
ma nella risposta occorre aprire W, committare **e** aprire A corrente,
e aprire ogni vecchia A. Il census finale EXP30 fornisce A packed da
13.154.672.538 / 14.334.320.538 / 15.513.968.538 B. Sono byte effettivi
della sorgente, non celle RNE ripetute o Fp3 densi.

| O | Visite W primo oracolo | Visite A per generazione | HBM lower primi oracoli, TB | Lower banda, s | Più lower merge W, s |
|---:|---:|---|---:|---:|---:|
| 0 | 1.024 | 1.024 | 158,252164 | 47,239452 | 52,884727 |
| 150 | 1.024 | 512 / 1.024 | 186,673720 | 55,723499 | 61,368774 |
| 300 | 1.024 | 512 / 512 / 1.024 | 215,699256 | 64,387838 | 70,033113 |

Queste cifre concedono gratis la disponibilità packed di A. Escludono
oracoli successivi, range A, altri prodotti di campo, PCG, inferenza e
serializzazione. Le continuazioni sono escluse già dalla banda sotto le
condizioni dichiarate. Non è un lower universale sulle PCS o sul prover.
Il commitment W installato si paga separatamente: altre 1.024 visite e
>=30,992529 s in questo metodo; includerlo nel confronto dei prefissi.

Il binario range compilato con CUDA 12.9.1 contiene **149 istruzioni
`IMAD.WIDE.U32` incondizionate** per merge valido, prima dell'uscita,
senza ciclo/call nel corpo. Su 640.151.453.695 merge, con 132 SM,
<=64 risultati multiply INT32/ciclo/SM e ceiling esplicito **2 GHz**,
questa sola classe impone >=5,645275 s. Il ceiling di clock è una
condizione dello screen, non una misura della macchina futura. Il bound
vale per il kernel generico compilato; fusioni/specializzazioni diverse
richiedono un nuovo census. La
[tabella NVIDIA](https://docs.nvidia.com/cuda/archive/12.9.1/cuda-c-programming-guide/index.html#arithmetic-instructions)
non autorizza conversioni da TFLOPS Tensor Core a prodotti Fp/Fp3.

## Alternativa minima: aperture per resti, cache e range coordinati

Conservare i nodi Merkle sopra sottoalberi da **4.096 foglie**, con gli
offset iniziali dei sali canonici. Per W e fino a tre A, questa cache
privata costa **188.743.552 B**: 167.772.032 nodi in byte e 20.971.520
offset in byte. Non contiene correlazioni riutilizzabili e non aggiunge
emissioni. Le query restano successive al commitment.

Dopo le query, al più 512 sottoalberi richiedono B=2^21 righe. B è un
**cap algoritmico fisso**, indipendente da N e dal numero effettivo q;
completare con punti distinti deterministici del dominio originale se
necessario. Per `Z(X)=prod(X-x_i)`, consumare i coefficienti sorgente,
pad privati originali inclusi, a blocchi high-to-low:

```
r <- (r * X^B + f_i) mod Z
```

Precalcolare FFT del reciproco di `reverse(Z)` modulo X^B e FFT(Z).
Il quoziente usa soltanto i B coefficienti alti invertiti: includere
anche quelli bassi causa alias ciclico. Due convoluzioni con fattore
fisso costano **quattro FFT di lunghezza 2B=2^22 per blocco**. Il test
ora esegue proprio questi quattro transform, con due precalcoli condivisi.
La FFT quadrata 2048² già compilata è riusabile; inverse, normalizzazione,
packing e pipeline remainder CUDA restano da collegare.

Per N coefficienti base, arrotondati a blocchi, il nucleo sorgente paga
**88N butterfly + 8N prodotti twiddle + 4N prodotti spettrali + 4N
normalizzazioni inverse**, una scansione sorgente; ogni butterfly include
un prodotto e due somme. Aggiungere shift del dominio, pad, layout,
costruzione reciproco/alberi e valutazione multipunto veloce. Questi
ultimi termini sono `P(q,h)` indipendenti da N con il cap fisso: i piccoli
helper quadratici del test non sono il piano canonico. Il requisito
`c_source*N + P(q,h)` è soddisfatto da questo **nucleo di apertura**;
non è ancora dimostrato per commitment, WHIR e intera costruzione.

Le righe ottenute devono coincidere con quelle originarie. Ricostruire
sali e sottoalberi inferiori, poi prendere i fratelli superiori dalla
cache. Non cambiano punti MAC, root, codec, ordine FS, pad o trust model.
Il confronto finito verifica divisione, righe selezionate, pad privati
non nulli, zeri pubblici e blocco iniziale parziale; manca il confronto
bit-per-bit contro l'intera PCS nativa e la sua disciplina NoPeek.

La prima proposta h=10/B=2^19 richiedeva 754.974.592 B di cache su tre A:
non entra con il range m25. Anche h=12 non entra nei 127.377.416 B liberi
di quella fase. La variante coordinata usa **cut=11, residente m=24**:
**29 visite W**, 740.982.521.855 merge e 3.469.226.278.261 mul Fp3 del
nucleo fattorizzato. Cambiare soltanto m senza il canopy lascia un picco
incompatibile. Il range A/D34 può usare cut=10/m24: 26 visite A e
1.571.622.485.383 mul Fp3 del medesimo nucleo, più getter/istogrammi/MAC.
Sono replay della stessa algebra range, non un protocollo indebolito.

## Schedule, liveness e picco allocato/riservato

Ordine FS invariato: fissare snapshot e output; messaggi dei producer e
MAC; istogrammi prima di alpha/rho; range W, range A e relativi target;
batch linear W con lambda dopo tutti i target; primi 15 round suffix-first;
seconda scansione e ultimi 20 round; PCS nel punto originale. I tempi
commit A e apertura non sono anticipati oltre le dipendenze del transcript.
Ogni riuso attende ultimo consumer e completamento GPU.

Piano di allocazione: una sola arena riservata da **6.442.450.944 B**;
la cache Merkle vive **dentro** l'arena durante tutte le fasi. La tabella
conta anche destinazioni fold fuori posto e istogramma W da 524.280 B.
Sono upper dei buffer nominati/cap proposti, non picchi misurati.

| Fase | Byte pianificati, cache inclusa | Fine vita e costi ancora da chiudere |
|---|---:|---|
| Canopy cut11 | 3.376.938.824 | Tree 1.610.612.688, child/eq 1.006.632.960, fold dst 503.316.480, scratch 64 MiB; rilascio dopo terminale top |
| Finestre Gram | cache + istogramma + slot 256 MiB | H <=24.576 B, child <=3.072 B, worker fissi; nessuna H per tutti i bucket |
| Range residente m24, W o A | 3.480.760.184 | Array/riduzioni 3.023.056.896 + scratch 256 MiB; rilascio dopo terminale |
| Suffix-first W, 15 round | C 2.848.456.704 + cache + scratch vivo | C rilasciata prima della seconda scansione; pesi/getter ancora da assegnare |
| Seconda scansione linear W | B/L 50.331.648 + cache + scratch vivo | Rilascio prima PCS; linear A e vecchie A separati |
| Commit PCS iniziale per coset | 6.197.150.296 | 5.739.381.472 nominati + cache + slot reader/hash 256 MiB + istogramma + output PCG 64 KiB; restano 245.300.648 B |
| Apertura per resti | 5.352.498.160 | Include output 2 GiB, alberi/fattori FFT, cache, metadata, reader/hash, PCG output e cap proof; dettagli sotto |
| Producer A/KV, WHIR successivo, PCG completo | Ignoto | Non assegnare a zero; nessun picco completo accreditato |

Per l'apertura, un piano prudente conserva tutti i polinomi, reciproci e
due trasformate fisse di ciascun nodo dell'albero bilanciato, anche quelli
non strettamente necessari: rispettivamente **402.653.176 / 369.098.752 /
1.476.395.008 B**. Una colonna alla volta usa quattro workspace FFT da
32 MiB, due livelli di resti da 16 MiB, un resto sorgente da 16 MiB,
punti da 16 MiB e twiddle da 32 MiB. L'output selezionato da 2 GiB vive
nel riuso dell'arena PCS, senza coset/frontier da 5,739 GB ancora vivi.
Aggiungendo cache, slot metadata 128 MiB, reader/hash 256 MiB, istogramma,
PCG output e **130.000.000 B di output proof**, i buffer nominati occupano
**5.352.498.160 B**, lasciando 1.089.952.784 B prima degli altri stati.
Gli slot e le FFT di grado inferiore richiedono ancora il port nativo;
questa è una prenotazione analitica, non una traccia di malloc. La discesa
multipunto con quattro FFT per nodo ha un upper di 248.034.361.344
butterfly per 128 colonne, oltre al nucleo sorgente e alla costruzione
degli alberi. Nessuna valutazione ingenua B² è ammessa come costo canonico.

Le altre righe della tabella escludono l'output proof: riservando anche lì
130 MB, il maggiore subtotal diventa **6.327.150.296 B** nel commit PCS,
con soli 115.300.648 B residui. Non attribuire quel margine al PCG completo
o ad altre allocazioni senza verificarle. Non si presume emissione anticipata
della proof per liberare memoria prima del punto consentito dal transcript.

Il top Merkle/offset completo è contato anche durante il commit corrente:
non si sottrae la cache in costruzione. Gli slot di scratch sono cap da
implementare. Il buffer output PCG proposto è 4.096 righe base, 65.536 B;
non limita automaticamente seed, OT, cGGM e altri stati del backend.

KV originale costa **4.915.200 B/token**. Prefisso accettato:
0 / 737.280.000 / 1.474.560.000 B; con coda pendente da 150 token:
737.280.000 / 1.474.560.000 / 2.211.840.000 B. Proposta: un solo buffer
KV modello persistente prenotato per 450 token, append nella coda
inutilizzata, promozione del cursore solo dopo accettazione. Questa
classificazione vale solo per KV originale, non per witness o workspace;
la coda pendente è sempre contata nel picco globale e non sovrascrive
il prefisso. Se l'implementazione usa staging temporaneo, conta nell'arena.

W + riserva KV450 + arena = **70.048.981.504 B**; rimangono
**9.951.018.496 B** sotto 80 GB per runtime/context e altri residenti
ammissibili. Non autorizza spostare temporanei fuori arena. Una copia
packed completa di A non entra nell'arena; W+A+arena superano già 80 GB
anche senza KV. A corrente e storica devono avere getter immutabili e
ricostruzione contata. Il **picco allocato e quello riservato completi
restano ignoti**. `cudaMemGetInfo` e zero spill ptxas non certificano
liveness integrata, allocator o assenza di trasferimenti di spill.

## Visite, traffico e lavoro ancora necessario

| Voce | Replay completo respinto | Variante per resti |
|---|---|---|
| Installazione W | 1.024 visite; upload esterno W 61.394.690.560 B distinto | Commitment ancora invariato |
| W per risposta, voci note | 26 range + 2 linear + 1.024 prima apertura = 1.052 | 29 range + 2 linear + 1 prima apertura = **32** |
| A corrente, voci note | 512 commit + 512 apertura + 26 range | 512 commit + 1 prima apertura + 26 range = **539** |
| Ogni vecchia A, prima apertura | 512 visite | 1 visita |
| W/A/KV totali, HBM totale | Non chiusi | Non chiusi; includere gli accessi dei getter A e di ogni ricostruzione |
| Esterno per visite W residente | Zero | Zero; nessuno spill ammesso |
| Trasporto esterno protocollo, input/output, installazione | Ledger distinto | Ledger distinto, nessun costo sottratto dalla risposta |

I 32 passaggi W noti della variante muovono 1.964.630.097.920 B di payload
W, esclusi temporanei. Non sono un totale HBM. Le 539 visite A sono
visite logiche; la loro generazione può leggere W/KV e rieseguire produttori.
Non si assume che A packed esista gratis nella candidata ammessa.

Ogni catena D34/D35 ha **12 oracoli dati**, oltre alle maschere. Il report
ora elenca tutti i domini e byte. Dopo il primo folding a 7 bit, il primo
switch W richiede 103.079.215.104 B encoded (4 colonne Fp3, 12 base),
A 51.539.607.552 B: anch'essi richiedono streaming. Lo stato folded W
iniziale costa da solo 6 GiB Fp3; A 3 GiB. Il `initialize_sumcheck` denso
con evaluations e pesi non diventa lecito grazie alla FFT. Vanno progettati
ricostruzione/retention di questi stati, maschere, sali e aperture, con
stesso terminale VOLE. Non moltiplicare erroneamente per tre le 128
colonne **base** del primo oracolo.

A ha 3.471 sorgenti e 2.328 produttori (fra cui 773 P0, 421 RMS, 892 RNE nel
census pertinente), 4.446 target correnti; W 775 e ogni vecchia A uno.
Le aperture sorgente sono 2/3/4 per risposta. I 526 alberi e 39 stream
privati del run completo sono un lifetime, non memoria simultanea.

PCG: 11.466.948 righe base richieste nel run, capacità 70.778.880. Il
solo componente point-query dà l'upper analitico per ruolo
`2*353.894.400 + 209*11.466.948 = 3.104.380.932` passi cGGM. Non è il
lavoro completo AES/OT/field/setup; conservare tutte le uscite MAC del
prover costerebbe 183.471.168 B. Servono consumo a batch, cap al materiale
vivo, conti di HBM/AES/field e trasferimenti distinti. Il bootstrap da
61.841.290 B rimane un conteggio wire condizionale, non tempo o memoria.

## Upper analitico e throughput minimo

L'upper completo richiesto ha la forma conservativa, senza overlap:

```
T_response <= sum_k [L_k_upper + sum_j work_kj/R_kj_min
                    + HBM_k/BW_k_min + external_k/BWext_k_min]
```

Le categorie k sono: inferenza; ricostruzione A/KV e producer/GKR;
range W; range A; linear W/A/vecchie A; PCS di tutti gli oracoli dati e
maschere; PCG/OT/MAC/FS; serializzazione/trasporto dipendente dalla
risposta; allocazione/launch/sincronizzazione/host. La somma di IO e
calcolo è qui prudenziale: ogni quantità va addebitata una volta; se si
usa un upper di kernel completo non riaggiungere il suo IO. Setup W e
bootstrap si riportano anche nei prefissi totali, senza nasconderli.

Per ottenere un numero finito mancano lavoro e service-rate floors
applicabili a diverse categorie; **l'upper di ammissione è quindi
+infinito, non 50 s e non una previsione di tempo infinito reale**.
Le soglie seguenti concedono tutti i 50 s a una sola voce e sono solo
necessarie; per un budget t_k usare `work/t_k`, con `sum(t_k)<=50`.

| Nucleo variante | Lavoro | Throughput minimo /50 s |
|---|---:|---:|
| Merge W | 740.982.521.855 | 14,820 Gmerge/s |
| Coefficienti W residenti, 18 mul/bucket | 201.326.556 bucket | 4,027 Mbucket/s |
| Fold W, H incluso | 1.006.637.247 scalari | 20,133 Mfold/s |
| Nucleo range W fattorizzato | 3.469.226.278.261 mul Fp3 | 69,385 Gmul/s |
| Nucleo range A fattorizzato | 1.571.622.485.383 mul Fp3 | 31,432 Gmul/s |
| Suffix-first W | 314.498.580.480 aggiornamenti | 6,290 Gaggiornamenti/s |
| Apertura per resti W, sorgente virtuale 2^35 prima dei pad | 88*2^35 butterfly | 60,473 Gbutterfly/s |
| Primo commit A, FFT sola | 3.023.656.976.384 butterfly | 60,473 Gbutterfly/s |
| PCS complete, getter A/KV, PCG, inferenza, serializzazione | Parzialmente ignoti | Soglia completa non disponibile |

Le righe range nucleo includono merge e coefficienti; non sommarle.
Il commit A aggiunge circa 8,80e12 mul di scaling generico per sorgente,
oltre a twiddle, hash e sali; non sparisce con l'apertura per resti.

## CUDA, harness e controlli ridotti

[`c71_fft_microbench.cu`](../../cuda/c71_fft_microbench.cu) implementa
trasposizione in-place a coppie di tile 32x32, FFT di riga shared,
twiddle+trasposizione, seconda FFT di riga e trasposizione naturale.
Non usa una seconda codeword. Array massimo componente 4 GiB più
32 MiB twiddle; transpose usa 16.896 B shared, row FFT <=16.384 B.
Input SplitMix64 seed `0xc701ff7025020001`; quick M256/batch8, completo
M2048/batch128. Il controllo GPU preliminare M64/batch2 copre anche tile
off-diagonal, prima delle allocazioni grandi. Non è stato eseguito.

Il [record statico su checkout pulito](../../benchmarks/results/c71-local-cuda-static-2026-09-13-ef2cdabc1afa.json)
fissa SHA `ef2cdabc1afabdb687e280092d0e07f8e40e30f0`,
archivi/toolchain, patch header, errori iniziali, log ptxas, dump SASS
del merge e controlli host dei binari CUDA. `git_dirty:false`,
`gpu_execution:false`, `credit:false`; nessun tempo GPU.

Range e FFT compilano localmente con nvcc **12.9.86**, `-O3 -std=c++17
-arch=sm_90 -Xptxas=-v`. ptxas: zero stack/spill in tutti i kernel;
range massimo 80 registri, FFT massimo 40. Non è una misura H100.
Toolchain temporaneo ARM64 SBSA dalle
[redistribuzioni NVIDIA 12.9.1](https://developer.download.nvidia.com/compute/cuda/redist/redistrib_12.9.1.json),
archivi verificati SHA-256. Il primo compile è fallito per le quattro
exception specification sinpi/cospi di glibc 2.41; la copia temporanea
header applica soltanto `noexcept(true)` a quelle quattro dichiarazioni
non usate. Conservare errore originale e hash prima/dopo; questa non è
una compilazione con toolkit intatto né il toolchain H100 di produzione.
Il problema corrisponde alla
[segnalazione NVIDIA](https://forums.developer.nvidia.com/t/error-exception-specification-is-incompatible-for-cospi-sinpi-cospif-sinpif-with-glibc-2-41/323591).

Controlli locali riproducibili, senza GPU e senza pesi reali:

```sh
ulimit -v 2097152
PYTHONDONTWRITEBYTECODE=1 timeout 60s pytest -q -p no:cacheprovider \
  tests/test_c71_streaming_screen.py tests/test_c71_range_microbench.py \
  tests/test_c71_query_remainder.py
PYTHONDONTWRITEBYTECODE=1 timeout 60s python3 scripts/run_c71_fft_microbench.py \
  --host-only --host-log2-m 3 --timeout-seconds 30
# Con CUDA devel disponibile; compila soltanto, non invoca --gpu:
timeout 60s nvcc -O3 -std=c++17 -arch=sm_90 -Xptxas=-v \
  cuda/c71_fft_microbench.cu -o /tmp/c71-fft-sm90
```

Gli harness [range](../../scripts/run_c71_range_microbench.py) e
[FFT](../../scripts/run_c71_fft_microbench.py) hanno input deterministici,
check CPU/GPU preliminare, metadata cloud obbligatori, controllo SHA/tree
prima e dopo il run, timeout e record append-only. Sono componenti;
l'input/harness della costruzione **integrata** non è ancora pronto.

## GO/NO-GO prima di qualsiasi spesa

| Gate | Controllo minimo successivo | Stato |
|---|---|---|
| Algebra/endpoint | Adapter piccolo nativo con righe, pad, sali, root, codec e MAC identici; rifiuto delle alterazioni | Identità finite passate, refinement aperto |
| CUDA | Compile/SASS; poi reader, inverse/remainder e pipeline hash rappresentativi con input piccolo | FFT/range compilati; reader e remainder CUDA mancanti |
| A/KV | Trace getter immutabile per tutte le ricette e O=0/150/300, conteggio ricostruzioni e dipendenze | Census descrittori disponibile, schedule fisica assente |
| PCS completa | Tutti i 12 oracoli per catena, maschere, stati folded, source-uniformity e salt seek | Ancora aperto |
| PCG | Trace AES/cGGM a batch, seed/state/OT, no pool bulk; costi di entrambi i ruoli | Upper componente soltanto |
| Memoria | Ogni buffer vivo, arena totale, allocated/reserved globale <80 GB, assenza di spill | Buffer nominati compatibili nella variante, totale ignoto |
| Tempo | Somma completa <=50 s sotto contratti applicabili; ogni lower compatibile | Replay completo escluso; alternativa non ammessa |
| Riproduzione e spesa | Clean SHA pubblicata, harness/input integrati, immagine/deadline/prezzo fissati, autorizzazione nuova | Gate non raggiunto |

Non si propone RunPod per il replay già escluso né si usa un microbench
veloce per accreditare il resto. Il precedente comando/preventivo puramente
indicativo resta nella storia Git: con lo steering corrente non è una
proposta attiva. Preparare un comando provider istanziato e un preventivo
solo dopo che la costruzione completa resta plausibile entro 50 s e
l'harness integrato è pronto; nessuna autorizzazione di spesa è acquisita.
