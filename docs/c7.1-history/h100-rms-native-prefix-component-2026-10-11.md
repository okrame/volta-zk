# RMS misto: primo componente GPU dai frame originali — 11 ottobre 2026

Il [record pulito `803f2fa8`](../../benchmarks/results/c71-certificates-rms-native-prefix-component-2026-10-11-803f2fa8.json)
conserva compilazione e parità H100 concluse alle18:33:41 UTC.
Il prototipo riceve12B originali/cella e assegnazioni pubbliche, esegue
il replay Booleano nativo, riunisce tutte le wire originali, traspone i
bitplane e valuta Eq sul suffisso originale. I conteggi BMMA rimangono
nei registri e diventano momenti Fp3 canonici prima della pesatura dei
gate. La posizione15 rimane una wire originale; nessuna riga ausiliaria.

Passano18 finestre per tre piccoli circuiti,17/257/4096 suffissi e punti
zero/uno/nonbase, inclusi padding, wire di programmi diversi e aggiunta
di un secondo chunk allo stesso accumulatore. Riferimento: circuiti
letterali separati dal piano di slot, Eq nel dominio originale e Fp3
diretto a nove prodotti.56 chiamate chunk,367.080 frame originali.
Non sono le159 ricette canoniche o una prova RMS/PCS completa.

Il compilatore riporta72 registri per thread nel consumer binario,
nessuno spill o stack frame;40 registri nei consumer lineare/pesatura.
Build3,205s monitorati, controllo completo0,803s con oracolo CPU incluso;
nessun tempo del dominio canonico o throughput HBM dedotto.
Allocazioni device richieste4.431.508B, H2D16.562.772B,
D2H176.256B e zero766.080B. Sono conti del componente ridotto;
allocator/driver/host temporanei non costituiscono capacità completa.
Massimo fisico stabile campionato690.806.784B; nessun errore risorse.
CPU AS64GiB; figlio CUDA senza cap AS; cap fisico e deadline originali.
GPU idle prima e dopo il processo, pod e guard ancora attivi.

Passano tre test dello screen e nove documentali. Il
[conto corretto dei contatori](../../benchmarks/results/c71-certificates-rms-native-prefix-component-2026-10-11-803f2fa8/builder-corrected.json)
addebita read/write BMMA per batch, poi la lettura della ricostruzione:
2.442.164.939.108.352B, oltre814.054.979.702.784B di zero separati.
Il precedente24.443.818.538.631.168B usava il numero di K tile;
[raw record e rettifica collegata](../../benchmarks/results/c71-certificates-rms-moments-census-2026-10-11-dc0064d7.json)
restano distinti. È il conto della vecchia schedule chunk32 con piani
u32 globali, non del prototipo fuso chunk512: quest'ultimo elimina quei
buffer, ma deve ancora ricevere il proprio conto completo/traffico.

Bundle privato `artifact/c7.1-pod/certificates-rms-native-prefix01-20261011`:
59file/1.274.103B, manifest SHA256
`0cc9cbcb8263856b39b7419515f1a29babba3c3f90c070ad5b8803aa9b2369a9`.
Record SHA256
`63a1e7b5ef0d349feb1db09d86bbddb6cd80e122edcc0226193deb57cc587457`.
Binario, PTX resource report, log e dati dello screen riverificati.

Il seguito preparato esporta piani originali da Rust con file esclusivi
e reference del replay layered originale, per159 programmi e tre pattern
di liveness. Le prime profondità previste sono1/48/99. Il controllo GPU
ricostruisce i12B dai bitplane originali e confronta tutte le wire/padding;
valida limiti, stadi, inizializzazione e assenza di race del packet.
**Compilazione e parità di queste ricette ancora pendenti.**

Il prototipo non è collegato al runtime comune/caller canonico. Prima
dell'uso completo servono ownership/arena e trasferimenti comuni, piano
pubblico validato, fold/core residuo, indici/byte/PCS e conto fisico.
Distributività, selector/mask/wire, Eq originale, ricostruzione/count
bounds/modulo, determinismo dei frame e lifetime/capacità CUDA restano
premesse non scaricate da nuovi lemmi Lean. Flag canonici invariati;
nessun nuovo setup AES, zero certificati e O=0 incompleto.
VM solo editing/controllo; termine calcolo23:43:00 e hard stop
12 ottobre00:13:00 UTC invariati dal riavvio.
