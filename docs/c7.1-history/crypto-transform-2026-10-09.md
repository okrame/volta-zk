# FFT naturale sul common owner — 9 ottobre 2026

Source `e96bd202d5279c8013c659649d2e703f99f7bd60`, baseline `9033c64`.
Il [record pulito](../../benchmarks/results/c71-crypto-transform-local-2026-10-09-e96bd202d527.json)
ha SHA256 `befa9ffe200051418fb3b690021f6091f6017daa010d41692bbc95968eb2ad74`.
Cinque controlli, cinque test Rust e diciotto Python passano su albero
pulito, con identità di sorgenti/binario verificate prima e dopo ciascuna
invocazione. I 28 artefatti da 84.021 B conservano comandi, log e manifest.
Non è stata compilata o eseguita CUDA; `credit:false`, goal ancora attivo.

## Componente e confine dell'integrazione

Le primitive naturali diretta/inversa riusano la FFT Goldilocks a cinque
passaggi nello stesso owner e stream. Accettano log N da 1 a 24, batch
fino a 2^20 e al più 2^28 word complessive. L'ordine dei coefficienti e
delle valutazioni è naturale; la trasformata inversa normalizza una sola
volta per 1/N. La geometria dispari ricompone le due metà nello scratch
e copia il buffer completo D2D, incluso nel ledger anche se un launch
successivo fallisce. Valori, scratch e twiddle sono distinti; binding di
lunghezza/orientamento, stato, tipo, owner e alias sono verificati.

Il batch di ciascun segmento è al più 32.767: le due metà dispari devono
rientrare nel limite grid.z 65.535 della
[documentazione NVIDIA](https://docs.nvidia.com/cuda/cuda-programming-guide/05-appendices/compute-capabilities.html).
Tre simboli ABI4 obbligatori preparano twiddle, trasformano e leggono
word base canoniche. La lettura esplicita è bounded a 2^20 word/8 MiB,
nega capability private e fasi sali attive. Nessun nuovo owner, stream,
buffer permanente, fallback CPU o reinterpretazione delle basi Fp3.

Questa è una **primitiva integrata**, non il collegamento del caller
query A. A quel source le query iniziali, resti/fattori e S1 rimangono CPU;
geometrie, finestre e ricostruzioni non cambiano. Le regressioni Tree W
conservano root, pad, lavoro e aperture con getter originale.

## Parità e provenienza

Il driver CUDA differito esegue un modello C++ della FFT a cinque
passaggi/dispari; l'oracolo indipendente è la DFT Rust P3. I 36 casi
confrontano tutte le word dirette/inverse, log 1..17 e batch ai bordi
32.767/32.768/65.530/65.536. Diciotto rifiuti terminali e tre librerie
con simbolo obbligatorio mancante sono verificati. Il modello e i tempi
host non provano scheduling CUDA, throughput GPU o velocità H100.

Il failure preliminare `transform-build-pre01` exit101/E0425 (`&mut0`)
è conservato: nessun test era partito; la correzione è `&mut 0`.
Le prove preliminari hanno `record_run:false` e tree dirty. La build
completa `transform-build-pre03` è separata: 56,7145 s e 2.515.423.232 B
RSS, un job, AS non limitato. La build pulita riusa esattamente quel
binario; le correzioni successive al modello C++ sono esercitate dalla
fixture dinamica pulita. Non attribuire al riuso il costo di una nuova
compilazione completa. I test sono seriali, AS 2 GiB/60 s e un worker.
RSS massimo test/descendenti 273.833.984 B; wall massimo 31,768 s.

## Risorse e lavoro ancora necessario

Shared massimo per riga 32.768 B, transpose 16.896 B. Owner host
37.288 B e Stats 152 B invariati; la tabella API Rust aggiunge 24 B.
La fixture osserva 8.389.120 B di capacità device e 24.176.129 B di
payload congiunto massimo, senza rifiuti nelle parità. Sono dimensioni
ridotte, non il picco canonico o una verifica della riserva fisica.

Per una query con q=2^20, il solo workspace di trasformazione è
4×(2q)×8 = 67.108.864 B: valori, scratch e due twiddle. Sono esclusi
fattori, finestra residente originale, low/high, pad, output host,
Tree/replay e altri owner vivi. Questo subtotal non ammette il caller.

Restano collegamento residente delle query A senza nuove ricostruzioni,
PCS S1, closure/GKR/range GPU e selezione attention secondo profilo,
conto simultaneo completo e misure separate di installazione, setup,
inferenza, prova e verifica. Compilazione sm_90, parità/performance e
picco fisico H100 appartengono a una nuova campagna autorizzata per
hardware e durata. La documentazione operativa resta nei cinque
[documenti attivi](../README.md).
