# C7.1 — accumuli e FFT W esatti, 8 ottobre 2026

Il goal locale rimane attivo. Questo passo collega, nelle fixture, W
sigillato → accumuli → FFT → foglia incrementale → Merkle strided nello
stesso owner. Il runner canonico non seleziona ancora questo componente:
rimangono import nel Tree, lifecycle della PCS e parità di transcript.
W/A selezionati restano 1.024/512 scansioni. Nessuna campagna H100 è
avviata o autorizzata; i risultati sono `credit:false` e
`gpu_execution:false`.

## Primitive e semantica

[c71_pcs_weight.cuh](../../cuda/c71_pcs_weight.cuh) descrive i tile
pubblici originali, senza nuova permutazione dei coefficienti. Il compiler
Plan emette offset, span e stride del packed W già condiviso. Il test
ragged confronta ogni indirizzo con `virtual_to_packed`; l'owner controlla
copertura contigua completa, potenze di due, span e W sigillato. Non
si duplica W e non si trasferiscono valori di campo al consumer host.

Per ogni colonna e riga un warp valuta 32 coset. Lane zero legge un peso
originale e lo distribuisce alle altre lane; il suffisso pubblico zero
interrompe il loop. Ciascuna lane accumula fino a 256 prodotti signed i16
per fattori canonici u64 in due limb unsigned, rappresentando esattamente
l'intero signed: |somma| < 2^87. La riduzione Goldilocks avviene dopo
il dot product; per l'encoding negativo si corregge 2^128 ≡ −2^32 mod p.
Il controllo host confronta **526.336 prefissi**, in 2.056 sequenze, con
modulo signed i128 indipendente. È un controllo finito, non un nuovo
lemma Lean di raffinamento CUDA.

I pad rimangono i 1.536 coefficienti di campo privati originali per
colonna, agli indici n+j. Potenze basse e alte ricompongono esattamente
ω^(coset·j), con gli stessi generatori Goldilocks P3. Non cambiano basi
Fp3, byte, sali, RNG, MAC, correlazioni, PCG AES o NoPeek. Le operazioni
PCS ricevono i propri pad; i producer originali non ricevono nuovi
challenge o monete della prova.

La FFT esistente del microbenchmark è estratta in
[c71_fft.cuh](../../cuda/c71_fft.cuh), con gli stessi cinque passaggi e
output naturale. Il launcher residente usa lo stream esplicito dell'owner
e restituisce errori CUDA; non alloca né termina il processo. L'FFT è
in-place su quattro colonne × 32 coset: nessun secondo ring completo.
Il microbenchmark riusa la stessa primitiva, incluse inversa e scala.
Il codice GPU è in [c71_pcs_weight.cu](../../cuda/c71_pcs_weight.cu).

## Parità, fallimenti e limiti

La fixture Rust confronta tutti i valori con `Code::coset_base`, poi
consuma le 128 colonne nel ring originale da otto. Confronta tutte le
foglie e tutti i cinque livelli Merkle dei gruppi strided. Tre geometrie:
(n,R,pad) = (64,4,6), (256,16,35), (4096,16,1536), sempre 32 coset,
includono negativo, limite signed, tile con stride e suffisso zero.
Sali dalla RNG privata originale in ordine naturale, completati a bande;
132 B di flag D2H per gruppo prima delle letture dei digest. Nessun
download di valori PCS. Non è ancora una root dell'intero Tree W o una
catena PCS/transcript che selezioni il nuovo commitment.

I 24 casi negativi verificano geometry, binding delle potenze, alias
pad/ring e low/high, copertura/span dei tile, identità Arc/layout W,
input incompleti, pad noncanonici, launch, fence e flag aritmetico.
Ogni errore è persistente e il close restituisce le capacità dopo cleanup.
Il loader richiede anche i cinque nuovi simboli PCS; ABI 4 e Stats
152 B restano invariati. La libreria host usa UBSan senza recovery;
non è un fallback di produzione né esegue lo scheduling dei kernel.

I test restano seriali, 60 s / 2 GiB AS. La build mirata è un job in
`rust/target`, da cwd `rust`, con dipendenze O2 e solo `volta-pcs` O0:
`--config profile.dev.package.volta-pcs.opt-level=0`. La build O2 con
AS 2 GiB fallisce per allocazione; quella senza AS raggiunge la deadline
60 s. Gli esiti si conservano. La build O0 completa in circa 34 s;
il suo RSS compiler di circa 2,47 GB è distinto dai RSS dei test. Non
si estendono i limiti dei test né si ricompila il workspace completo.
Il confronto temporale Rust O0/C++ O2 ha scope diversi e non è un
rapporto di accelerazione.

## Conto del componente e lavoro candidato

Per W n=2^28, R=2^20, 4.096 coset e 128 colonne:

| Capacità device | Byte |
|---|---:|
| Ring otto colonne × 32 coset | 2.147.483.648 |
| CV incrementali | 1.073.741.824 |
| Potenze basse 32×R | 268.435.456 |
| Potenze alte 32×257 | 65.792 |
| Twiddle FFT R | 8.388.608 |
| Pad originali | 1.572.864 |
| Frontier di sette livelli | 234.881.024 |
| Banda sali 65.536 foglie | 2.097.152 |
| Flag allineato | 256 |
| 3.156 tile da 40 B, capacità allineata | 126.464 |
| **Subtotal device del componente** | **3.736.793.088** |

L'envelope host dei payload nominati aggiunge cursori 8.388.608 B,
offset subtree 8.388.608 B, cache superiore 67.108.832 B, pad originali
e staging 1.572.864 B ciascuno, sali 2.097.152 B, tile 126.240 B e
owner C++ 37.064 B: subtotal 89.292.232 B. Somma conservativa fra
fasi 3.826.085.320 B, non picco misurato. Sommando l'upper device replay
esistente inclusivo dei residenti 785.789.696 B si ottengono
4.611.875.016 B, prima di header/capacità container host, Plan/profili,
tabelle host e altri owner attivi. Il conto congiunto completo della
schedule integrata resta da verificare; il tetto 5.905.580.032 B e
riserva/margine da 256 MiB ciascuno non cambiano. Le allocazioni native
passano dallo stesso budget prima di cudaMalloc.

La shared memory FFT è 16.896 B per CTA transpose e fino a 8.192 B
per CTA row; stack, registri, spill, driver e picco fisico restano
misure hardware. Il ring va rilasciato prima delle uscite Merkle e le
potenze non necessarie prima delle fasi successive; la schedule effettiva
e questi lifecycle non sono ancora integrati nel runner.

Una visita di ogni coefficiente per gruppo da 32 implica 128 scansioni
equivalenti: 7.858.520.391.680 B di letture logiche W, contro
62.868.163.133.440 B iniziali. Restano 125.736.326.266.880 contributi
originale×coset e 805.306.368 contributi pad×coset, oltre a riduzioni,
potenze, FFT, sali e hash. Sono conti analitici, non banda fisica,
visite misurate sulla H100 o tempi completi. Il confronto Tensor Core
a limb esatti rimane aperto; non si seleziona una variante MMA senza
parità e confronto di lavoro/memoria/tempo. A resta separata.

## Prossimo passo

Importare il componente nel Tree W canonico, con sali/seek, cache,
aperture e transcript originali, contabilità di tutti gli owner e
benchmark ridotto pertinente. Poi collegare A residente alla PCS senza
download per riga e ottimizzare il resto secondo il profilo. Γ mantiene
le identità: W, scale, tabelle e producer numerici originali sono invariati.
