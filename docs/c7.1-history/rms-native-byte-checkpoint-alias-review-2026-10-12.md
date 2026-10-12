# Byte GPU — alias del checkpoint rifiutato prima della layer

Revisione statica del candidato `bfb8b0e4`, senza compilazione o test.
Il nuovo output pubblico `checkpoint` era controllato per span/alignment,
ma poteva sovrapporsi a point, range o feature in ingresso. La scrittura
finale del checkpoint avrebbe modificato quell'input del caller dopo il
fence. Il consumer ora rifiuta tali alias prima di allocare o trasferire
la layer; coefficiente e terminale restano invariati nel percorso di errore.

È preparato il30º rifiuto nel test owner, che passa un puntatore dentro il
point come output checkpoint. Il precedente elenco29 e il [piano iniziale](rms-native-byte-implementation-prepared-2026-10-12.md)
rimangono la fotografia del candidato iniziale. Il nuovo test non è stato
eseguito: pod EXITED/runtime assente, durata aggiuntiva ancora senza risposta.
Nessuna build/test/screen sulla VM, nessun nuovo esito o credito GPU.

Restano necessari compilazione/link, fault/owner, figli densi di tutti gli
otto livelli, passaggio streaming/checkpoint osservato, wire/FS/MAC e caller
RMS/PCS originali. Nessuna selezione canonica o estensione della campagna.
