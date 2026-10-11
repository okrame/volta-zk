# C7.1 — pesi del prefisso RMS e condivisione pubblica, 11 ottobre 2026

Il sourcewise GKR visita prefissi consecutivi. Mantiene ora il prodotto
lungo il percorso MSB e ricalcola soltanto il suffisso cambiato: nessuna
divisione, compresi challenge zero e uno. Ogni prefisso riceve lo stesso
peso Eq originale e la traversata del checkpoint non cambia. Correlazioni,
FS, endpoint MAC, circuiti, selettori e quattro coefficienti restano identici.
La giustificazione algebrica è l’associatività del prodotto Eq originale;
non esiste un nuovo lemma di raffinamento Rust/Lean per questo percorso.

Per N=2^c e una profondità, i prodotti del solo peso di prefisso passano
da N·c·(c−1)/2 a 2N·c−4N+4; le sottrazioni sono N·c−2N+2.
Il percorso contiene al massimo 29 elementi Fp3 per il dominio ammesso,
e il ledger aggiunge un bound conservativo di 30·24=720 B alle fasi RMS.
Il core da 844.006.203.160.300 prodotti Fp3 per risposta e i callback
originali **non** sono ridotti da questa modifica. Nessun guadagno di tempo
canonico o target 65 s è attribuito.

Preflight locale: build mirata 57,924 s, RSS aggregato massimo
2.600.718.336 B entro 3 GiB/120 s. Il nuovo controllo esaustivo dei prefissi
fino a nove bit passa su punti estensione e zero/uno. Passano coefficienti
contro fold denso e wire completa della fixture mista con FS, consumo RNG,
verifier ed endpoint MAC originali; nessuna prova del modello reale.

Uno screen distinto compila le 159 ricette originali ricavate dalle 421
norm del piano O=0 e conta tutte le 99 profondità: 36,433 s e RSS massimo
506.040.320 B, entro AS 2 GiB/60 s. Raggruppare gate identici per supporto
del selettore darebbe 13.139.543 contro 59.434.260 prodotti per coppia
nel caso di supporto completo, rapporto 0,221077. Esclude pruning pubblico,
primo round Boolean, costruzione, replay e tutto il runtime. **Non è
un’implementazione selezionata, né il nuovo costo della risposta.**
Lo screen è conservato per valutare una futura riduzione esatta del core;
il percorso RMS completo resta irrisolto, zero certificati.
