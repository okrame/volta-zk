# RMS tail — fixture ragged preparata

Il tail per programma usa128 thread con stride sui gate; il prefisso
comune divide i gate selezionati in chunk512. Il precedente oracolo denso
usa pochi gate e non isola queste due frontiere, benché il159/99 confronti
il wire di ricette originali più grandi. È preparato un test CUDA ignorato
che confronta ogni coefficiente e terminale con il percorso denso CPU
originale su128 celle padded/125 vive, tre programmi e due profondità.

Gate per programma/profondità:129/513,257/1.025 e513/769; operatori
And/Xor/Copy, indici differenti e conteggi non multipli dei blocchi.
Tre casi includono challenge generali, zero/uno e punto cella Booleano
con selector nulli. Fixture di gate pubblica, senza pretesa di predicato
RMS valido o certificato. Nessun nuovo protocollo o lemma Lean.

Il helper condiviso conserva l'oracolo14 bit originale. I test restano
da compilare/eseguire sul pod dopo AB/BA, senza carichi concorrenti al
confronto temporale. CPU AS64 GiB, CUDA senza cap AS, monitor fisico/arena
e deadline invariati. Fonte pulita via Git HTTPS; binario CUDA tail già
congelato con SHA c0e0448d, harness Rust nuovo con sua provenienza.
Nessun calcolo pesante sulla VM e nessuna estensione della campagna.
