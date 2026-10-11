# RMS misto: fixture onesta corretta e parità composta — 11 ottobre 2026

Il [record pulito `9e00a8c1`](../../benchmarks/results/c71-certificates-rms-moments-rust-parity-2026-10-11-9e00a8c1.json)
conserva il controllo concluso alle18:24:13 UTC sullo stesso pod/H100.
Le assertion del replay letterale confermano il predicato di ogni cella
onesta dopo la correzione factor12→4. Il test composto passa1/1 in5,50s
(monitor5,605s): wire, FS, MAC e correlazioni originali coincidono;
il verifier RMS/PCS originale accetta il caso onesto e respinge le
alterazioni previste, incluso il cambio PCS che conserva il predicato.

Passano anche coefficienti Goldilocks1/1 e nove controlli documentali.
Build451,385s, massimo fisico stabile campionato2.966.953.984B;
test wire186.253.312B. GPU zero nei campioni di tutti i controlli.
AS CPU64GiB, un job/worker, cap fisico e scadenze originali invariati.
Nessun errore risorse; i campioni non sono picchi completi.

La fixture ha tre piccoli programmi e correlazioni ideali. Il builder
Rust misto resta `cfg(test)`, max512 celle, con pesi per sorgente;
non è un caller CUDA o una prova canonica. Nessun credito per AES,
modello, PCS canonico, tempo completo, conto simultaneo o raffinamento.
I [due negativi precedenti e la rettifica](h100-rms-moments-census-2026-10-11.md)
rimangono conservati con i loro hash, senza trasformarli in pass.

Bundle privato `artifact/c7.1-pod/certificates-rms-moments04-rust03-20261011`:
47file/37.255.100B, manifest SHA256
`c8578b9a2a5bfdaba952fb7b9acac768c42b3ac0f87d759b202d317aabe83ac8`.
Record SHA256
`bc84933da973d46537a804d779017f12c8f06bd6264e13bb1030ed39046a1786`.
Binario e log riverificati prima del record; nessun input originale modificato.

Il conto logico dei contatori nel precedente screen usava il numero di
K tile. Il consumer BMMA esistente accumula i tile nei registri, leggendo
e scrivendo i contatori una volta per batch; la ricostruzione li legge
ancora una volta. La rettifica preparata addebita tre accessi per batch,
oltre alla scrittura di zero distinta. Raw record precedente immutato;
nuovo screen ancora da eseguire sul pod.

Il prototipo CUDA preparato parte dalle12B originali e dai programmi
pubblici, riunisce le wire di tutti i programmi, mantiene la posizione15
originale e valuta Eq sul suffisso originale. Ricostruisce i conteggi nei
registri, quindi applica i pesi originali a chunk512 prima di accumulare
Gram e lineari. Nessun piano u32 globale. Compilazione/parità H100 ancora
pendenti; non è collegato al runtime comune o al caller canonico.

Prima dell'uso completo restano necessari parità dei159 programmi,
integrazione nel medesimo owner/arena, conto di host/device/trasferimenti,
tail fold/core originale e premessa di raffinamento. Nessun nuovo lemma
Lean scarica distributività, indici selector/mask/wire, determinismo dei
frame, ricostruzione/modulo/count bounds, capacità o lifetime CUDA.
Pod/guard attivi, VM solo editing/controllo, zero certificati canonici;
O=0 incompleto, O=150/300 non iniziati e nessun nuovo setup AES.
