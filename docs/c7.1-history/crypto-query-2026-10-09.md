# Query iniziali A sul common owner — 9 ottobre 2026

Source `46d295ef4ea69ea6130a64c411d982d8fc1cba9d`, baseline `9033c64`.
Il [record pulito](../../benchmarks/results/c71-crypto-query-local-2026-10-09-46d295ef4ea6.json)
ha SHA256 `20d28e42c5aeff82b87ed127e2fa11bac0c68851ea0f592dba6fb84c7469de1b`.
Dieci invocazioni comprendono una build calda, nove test Rust e diciotto
Python riusciti, con identità source/binario controllate prima e dopo
ogni invocazione. Il manifest conserva 61 artefatti. `credit:false`,
goal attivo, CUDA non compilata/eseguita e nessuna campagna H100 autorizzata.

## Componente e parità

Il caller delle query iniziali A è collegato a `NativeQuery` sul medesimo
owner/stream numerico. Le finestre originali restano bounded a 256 MiB,
con i blocchi high-to-low delle stesse due colonne. Resti, shift dei pad
e discesa usano le FFT naturali base; fattori pubblici/reciproci/shift
sono preparati CPU. Quattro simboli ABI4 obbligatori (+32 B API Rust)
sono `c71_pcs_query_low`, `c71_pcs_query_remainder`,
`c71_pcs_query_shift`, `c71_pcs_query_add`.

I 75 casi contro Horner mantengono richieste di finestre identiche al
riferimento, live zero/parziale, padding, ordine inverso e duplicati.
Il reader riceve solo runtime/intervallo pubblico originale; spettri e
pad PCS restano nel consumer. Non scarica byte originali, non chiama
getter o reader host sostitutivi. Sono verificati quattro rifiuti reader,
25 owner e quattro librerie con simbolo obbligatorio assente, inclusi
letture private/fasi sali. PCS v³=v+1 e MAC u³=2 restano distinti.

La catena D10 usa query native uncached e commitment iniziale CPU,
confrontando wire completo, FS/RNG, endpoint MAC originali e risultati
di due verificatori. Il resto della PCS extension rimane CPU. Regressioni
Tree W/A conservano root/aperture/sali/pad e lavoro. Il commitment iniziale
A conserva 512 ricostruzioni; non ne sono aggiunte per limb o colonna.
Questo verifica il collegamento software su driver differito, non i
kernel CUDA, l'intera prova canonica o prestazioni H100.

## Compilazione e failure conservati

La build completa preliminare `build-pre09` impiega 57,0889 s, RSS
2.442.866.688 B e picco aggregato campionato 2.493.812.736 B. Un job,
crate O0, dipendenze O2, 256 codegen unit, incremental disabilitato,
overflow checks conservati e linker LLD della toolchain con un thread.
Il comando è `cargo rustc --lib --profile test`; la
[ricetta corrente](../c7.1/local-tests.md#compilazione-mirata) deriva il
percorso LLD da sysroot/host, senza nuovo linker o home codificata.
[Cargo](https://doc.rust-lang.org/cargo/commands/cargo-rustc.html) documenta
la modalità test e gli argomenti del solo crate;
[LLD](https://lld.llvm.org/) è il linker ELF già presente.
AS della build non limitato; deadline 60 s. La build pulita calda riusa
esattamente il binario da 92.281.232 B con SHA256
`acf518266cbf68f8cc67d5036865017ac5670e0507549ea4ba462364d2680122`;
il suo costo non sostituisce quello della compilazione completa.

`build-pre01` exit101/E0283 è conservato: tipo errore `Result` ambiguo,
corretto con `Result<DenseMatrix<Goldilocks>, String>` esplicito; nessun
test partito. I sette `build-pre02`…`pre08` exit124 scadono a 60 s,
senza eseguire artefatti incompleti o estendere il limite. Preliminari
dirty con `record_run:false` restano distinti dalle verifiche pulite.
Il rusage dei figli uccisi prima del reap è incompleto; pre06–09
aggiungono campioni dei discendenti vivi ogni 100 ms. Non derivarne
speedup LLVM, C++/Rust o GPU. I test puliti sono seriali, un worker,
AS 2 GiB/60 s: RSS massimo 297.017.344 B, wall massimo 49,8142 s.

## Risorse e lifetime

Il record dettaglia q≤2^20, fino a 128 colonne, pad≤1536 e 93 descrittori
query. Al cap, subtotal device 1.125.647.872 B più flag gather allineato
256 B; host matrice 1.073.741.824 B e staging colonna 8.388.608 B.
Sono esclusi costruzione pubblica prodotti/cache DFT/conversioni CPU,
Tree/replay, righe/sali/path già aperti, numerica, PCG/maschere,
prove/codec, entrambi i ruoli e margini fisici: `joint_admitted:false`.
La suddivisione corrente è in [specs](../c7.1/specs.md#aperture-e-fft-naturale).

I temporanei query sono ritirati prima della rigenerazione/copia delle
righe del batch corrente; le righe dei batch precedenti restano vive.
Retention S1 inizia dopo apertura/rilascio del predecessore A, senza
sovrapposizione con scratch query iniziale. Ciò non ritira gli snapshot
o le cache iniziali condivise. Owner host 37.288 B e Stats 152 B invariati.
Tempi Rust O0 e modello C++ O2 non consentono una comparazione di speedup.

Restano extension/S1 residenti, caller lineare, GKR/range/PCG e profilo
delle sincronizzazioni. Il nuovo owner lineare e gli helper S1 preparati
dopo questo source non sono coperti dal record. Conto simultaneo completo,
misure separate installazione/setup/inferenza/prova/verifica, compilazione
sm_90 e parità/prestazioni fisiche richiedono lavoro successivo; nuova
H100 e durata richiedono autorizzazione. I cinque
[documenti attivi](../README.md) rimangono l'autorità operativa.
