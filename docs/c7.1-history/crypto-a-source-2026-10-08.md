# Consumer PCS A residente — 8 ottobre 2026

Checkpoint locale del goal H100, successivo al
[Tree W](crypto-w-tree-evidence-2026-10-08.md). Le istruzioni correnti sono
nei cinque documenti [C7.1](../c7.1/design.md). Nessun hardware, durata o
campagna è autorizzato da questo checkpoint. Il goal rimane attivo.

## Decisione e motivo

A conserva quattro coset e tutte le 128 colonne per ricostruzione. Una
trasposizione della schedule W a otto colonne aumenterebbe i replay
numerici; il consumer nuovo mantiene invece 512 ricostruzioni sul pinned.
Due buffer da 64 colonne rispettano il cap per allocazione di 2 GiB.
Le coordinate derivano dalle stesse tessere di `emit_row_bytes` e del
gather range, senza permutazione o vincolo di finestra range. Il consumer
riceve originali residenti dallo scanner, senza scaricare ogni riga.

La prima ricostruzione aggiorna anche un istogramma privato di 256 byte
possibili. Non si aggiunge una ricostruzione per preparare il range.
Potenze alte e quattro accumuli modulari esatti precedono pad originali,
potenze basse e le FFT finite esistenti. L'ordine delle emissioni non
modifica la somma nel campo. Le due metà residenti alimentano direttamente
le 18 compressioni B12 della foglia: nessun ring aggiuntivo o CV persistente
per A. Sali a bande e Merkle strided riusano le primitive già verificate W.

`c71_pcs_source.cuh/.cu` non aggiunge un owner o uno stream. L'ABI resta 4,
con cinque nuovi simboli obbligatori, kind pending 15/16, tile/shape da
56/40 B e una transazione fissa da 88 B nell'owner. Il record di transazione
non contiene monete. Il costo host del contesto è ora 37.152 B (+88 B).
Nessuna allocazione pending è pubblicabile; copertura, pad/FFT e flag
precedono i valori base, mentre tutte le bande precedono i digest.

## Verifiche preliminari e limiti

La build mirata offline/locked con un job e root Rust O0 termina in
55,84 s; RSS compiler 2.482.995.200 B, separato dai limiti dei test.
Il filtro `c71_b12_native_source_` passa tre test in 9,86 s, entro
60 s / AS 2 GiB, con massimo RSS test/compilatori discendenti 217.444.352 B.
Le tre geometrie `(n,R,pad,coset iniziale)` sono `(8,4,3,0)`,
`(32,16,35,28)` e `(512,4,1536,2044)`: quattro coset, tutte le 128 colonne,
sorgenti i16/i32/i48 ragged, stride/offset nonzero, blocchi in ordine
inverso, 128 contributi e pad oltre n/R. Il modulo e le FFT sono confrontati
campo per campo contro Rust/p3; foglie e due livelli Merkle contro B12.
Il massimo payload congiunto ridotto è 4.965.783 B, owner W non esentato;
zero rifiuti nelle parità. Le capacità native sono liberate completamente.

Il test distinto del codec usa bias per addizione indipendente agli estremi
signed, mentre i 28 errori verificano owner, state/coverage, input pending,
span, codec, potenze di altro gruppo, binding delle metà/istogramma,
launch/fence/flag, pubblicazione incompleta e terminalità senza retry.
La fixture dei producer esegue solo Affine/RNE: 6.451.200 byte originali,
36 descrittori, otto byte di flag D2H e nessun upload o download di riga.
Errore del sink arresta l'owner comune alla prima tessera rifiutata.
La promozione conserva il replay storico di A; un primo test fallito
assumeva erroneamente il contrario, poi è stato corretto. Anche una build
con errore nel solo oracle del test Merkle viene conservata separatamente.

I tempi di accumulo/FFT della fixture C++ O2 e riferimento Rust O0 sono
registrati con la diversa ottimizzazione esplicita: nessuno speedup è
ammesso da quel confronto. Il driver simulato esegue codice host e lifecycle,
non i CAS, shared atomics o scheduling dei kernel CUDA; nvcc/H100 non sono
disponibili in questa VM. Non è stato eseguito D34/D35 o un modello reale.

## Conto candidato canonico, prima dell'integrazione

R=2^20, 2.048 coset, gruppi da quattro, cut=4.096: 512 ricostruzioni.
Capacità comuni alle fasi: valori 4.294.967.296 B, frontier 301.989.888 B,
twiddle 8.388.608 B, pad 1.572.864 B, banda sali 2.097.152 B. Accumulo:
4.642.576.672 B con potenze/conteggi/flag. Hash dopo rilascio delle potenze:
4.743.233.792 B con digest e flag. Non sommare i due picchi.
Host nominati 49.846.528 B e upper device replay 785.789.696 B danno
5.578.870.016 B conservativi, prima degli altri owner host. Restano
326.710.016 B nel payload imposto 5.905.580.032 B. La riserva fisica di
256 MiB e il margine operativo rimangono invariati e non misurati.
Per W, gli 88 B host aggiuntivi portano lo screen a 4.611.875.360 B;
evidenze e conti storici precedenti restano immutabili.

Il budget comune addebita tutte le capacità effettive, entrambi i ruoli e
staging. Questo envelope non ammette il percorso completo e non dimostra
che i restanti owner rientrino. Γ resta riusabile: numerica, tabelle,
scale, token e W sono invariati. NoPeek, MAC originali, basi Fp3,
correlazioni monouso, PCG reale AES e fail-closed sono invariati.

## Lavoro restante

Il componente non è ancora selezionato nel Tree o runner A. Integrare il
consumer con gli originali residenti, mantenere cache/seek dei sali e
istogramma senza scan extra, verificare root/aperture/transcript/MAC e
budget simultaneo. Poi proseguire con aperture/extension/contrazioni,
confronto Tensor Core W, GKR/range/attention e sincronizzazioni secondo
il profilo. Resta aperto il costo dei sali CPU; il D15 W completo non
cached oltre 60 s rimane una failure, non un pass. Il goal si conclude
con preparazione locale completa prima della nuova campagna autorizzata.
