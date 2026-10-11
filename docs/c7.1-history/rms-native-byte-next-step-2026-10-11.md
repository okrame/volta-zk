# RMS byte — prossimo consumer e limiti

La [parità tail](h100-rms-tail-program-reduction-parity-2026-10-11.md) e il
[confronto AB/BA](h100-rms-native-paired-2026-10-11.md) conservano l'endpoint
byte CPU contracted32 MiB. Il backend completo resta aperto; questo è
un piano implementativo, senza nuovo risultato o ammissione hardware.

Il [caller mapped](../../rust/volta-pcs/src/c71_matrix/rms/gkr.rs) invoca
il prover byte prima del ritorno di `prove_native_mapped_sourcewise`.
Il proprietario ritira `RmsSourceToken` dopo quel ritorno. Il checkpoint
P/S/Y già registrato resta quindi vivo e può servire lo stesso endpoint,
senza nuova copia del checkpoint o letture del produttore. I consumer
cella e indici terminano prima del byte. Questo lifetime deve essere
conservato e verificato nel nuovo consumer, compresi cleanup incerti.

L'implementazione successiva parte dalle callback coefficienti/terminali
di [byte_function](../../rust/volta-pcs/src/c71_matrix/byte_function.rs)
e dalla [contrazione esistente](../../rust/volta-pcs/src/c71_matrix/byte_function/contraction.rs).
Conserva tutti gli otto livelli, le16 lane e la baseline del byte zero:
il supporto pubblico e il numero di byte di ciascun programma determinano
le letture, comprese lane e padding nulli. Trasformazioni pubbliche,
challenge, claim, FS e MAC rimangono quelli originali; PCS termina negli
stessi valori autenticati. Il terminale recupera i quattro figli originali
da istogramma pesato dei byte, non da valori diagonali trattenuti.

Serve una capability privata distinta legata al sorgente mapped e al
Runtime. Nessun import/export tramite NumericProducer; selezione GPU
esplicita senza fallback CPU su API/GPU mancanti. Begin/round/terminale
devono possedere tabelle/point/staging H2D/D2H fino al fence positivo,
bloccare source-retire mentre il byte è attivo e rimborsare solo dopo
ritiro certo. Due stati limitati e la loro sovrapposizione vanno contati
insieme a LUT, supporti, fattori Eq, istogrammi, pubblicazione, shadow,
owner e capacità Rust già viva. I32 MiB CPU non autorizzano altri32 MiB
fuori dal conto comune; allowance driver/mapping resta da scaricare.

Prima di selezionare il consumer: rifiuti owner/sorgente/fence/H2D/D2H,
parità di ogni coefficiente e terminale contro i figli densi originali,
zero/uno e supporti/lane ragged, poi wire/FS/MAC159/99 e caller RMS/PCS
con alterazioni respinte. Il conto simultaneo e il costo delle riletture
del tail restano indipendenti:209.567.637 launch analitiche non ricevono
credito di tempo dal benchmark ridotto. Anche statistica, modello reale,
real/AES, certificato e journal restano aperti. Nessun nuovo setup o
trial canonico è avviato da questo piano.

Tutto il calcolo resta sul pod autorizzato, VM solo editing/controllo.
La finestra originale non si estende; dopo il termine occorre nuova
autorizzazione di durata per altri carichi pagati.
