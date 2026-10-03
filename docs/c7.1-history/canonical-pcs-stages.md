# Stadi PCS e preparazione P/Q — 3 ottobre 2026

Segue le [riduzioni sorgente](canonical-residual-scan.md); le istruzioni
correnti restano nei [cinque documenti attivi](../c7.1/design.md).
Il [record pulito cc5db06](../../benchmarks/results/c71-pcs-stages-local-2026-10-03-cc5db06c1796.json)
conserva 32 test Rust, 18 Python, due rifiuti CLI e build/lint passati.
Preserva il tipo `Vec` omesso nel test Rust e le due asserzioni Python
fallite durante lo sviluppo, poi corrette. La
[correzione collegata del cap testato](../../benchmarks/results/c71-pcs-stages-block-cap-correction-2026-10-03-cc5db06c1796.json)
distingue 1.024 nei confronti diretti da 2.048 nei test integrati D12;
non modifica risultati o output e non aggiunge esecuzioni.

Il replay seleziona ora la schedule completa degli oracoli W/A: iniziali
con 128 colonne base e coset 2^22; extension con quattro colonne Fp3,
ossia 12 limb base. S1 usa 2^24 righe per coset, S2 2^22, i successori
al più 2^23. Le altezze S1 sono 2^29/2^30 per A/W; S2 2^27/2^28.
Il guard dell'albero verifica la stessa selezione prima di allocare o
consumare sali. Non riappare il cap S3 2^24 respinto quando S1 mantiene
la capacità intera. Le configurazioni ridotte conservano il proprio
coset piccolo; un test attraversa tutti gli stadi D34/D35 senza allocarli.

Il residuale ammette domini fino a D35. Oltre D16 limita il primo
prefisso a sette bit; Eq rimane fattorizzato e il blocco P/Q è limitato
a 2^21 elementi, non all'intero dominio. Q e il reciproco dipendono
solo dalle basi Pow. Fold e scaling aggiornano le ampiezze mantenendo
gli stessi buffer; dopo due fold la cache viene eliminata prima del
commitment successivo. Il batch di nuove basi invalida la preparazione.
La riduzione della nuova claim ha il proprio setup temporaneo, senza
coesistenza con la vecchia cache. Per i piccoli blocchi finali basta il
prefisso del reciproco già preparato; nessuna divisione per le basi.

Il conto nominato aggiunge capacità reali dei vettori P/Q, descrittori e
un upper del payload dei due twiddle P3. Non è la misura simultanea del
programma: restano allocator, metadata DFT, intermedi FFT/numeratori,
getter, S1, maschere, cache Merkle, verifier e Seed6. Il rilascio dell'owner
CPU non dimostra rilascio RSS/HBM. Il ledger analitico distingue ora
l'implementazione P/Q CPU presente dalla validazione canonica e da CUDA,
entrambe ancora assenti; i suoi conteggi non diventano misure del codice.

I confronti ridotti usano potenze dirette fino a blocchi 1.024, più basi
zero/uno/ripetute ed extension. La prova PCS D17 controlla il primo fold
a sette bit e il percorso oltre il vecchio cap D16: lo scanner rimpiazza
un getter originale che va in panic, S1 è trattenuta e tutta la prova
deve coincidere col riferimento denso, inclusi transcript, codec, RNG e
MAC originali. Il test del lifecycle controlla l'identità del buffer
attraverso la prima sfida/scaling e la sua rimozione dopo la seconda.

Nessuna esecuzione D34/D35, calibrazione reale o GPU. Il supporto delle
shape non è readiness e non attesta 65 s o il picco. Restano range,
workspace query/multipunto, kernel densi, integrazione CUDA e contabilità
simultanea completa, poi composizione canonica positiva. Pesi/H100 e
spesa richiedono autorizzazione; l'hard stop provider resta. Zero
certificati canonici, obblighi Seed6 aperti e continuazioni oltre 40 MB.
