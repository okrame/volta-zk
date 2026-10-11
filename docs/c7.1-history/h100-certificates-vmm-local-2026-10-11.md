# C7.1 — backing differito A/KV, preflight locale 11 ottobre 2026

Lo spike esterno al pool del trial a-async04 rimane non attribuito. Questa
ipotesi riduce una sovrapposizione concreta senza cambiare la relazione:
le colonne A che contengono soltanto padding pubblico restano prive di
backing durante il producer. Vengono allocate, azzerate e popolate con i
pad originali prima delle stesse FFT e hash. O=0/150/300 hanno 99/107/116
colonne originali; i 512 gruppi, 128 colonne e quattro coset non cambiano.
Non si afferma che la causa dello spike sia risolta prima della misura.

Il KV mantiene lo stesso indirizzo virtuale e handle condiviso per 450
righe. Inizialmente sono mappate 150 righe; il primo append oltre il backing
mappa la coda restante. Nessuna copia o sostituzione del buffer aggira il
contatore condiviso `initialized` o il rifiuto dei fork. Le scritture
numeriche/upload generiche rifiutano i KV VMM; gli input leggono soltanto
il prefisso scritto. Le capacità fisiche arrotondate, anche parzialmente
allocate durante un errore, rimangono conteggiate fino al cleanup certo.

Il mapping segue le [API VMM CUDA 12.8](https://docs.nvidia.com/cuda/archive/12.8.0/cuda-driver-api/group__CUDA__VA.html):
riserva dell’indirizzo, allocazione fisica, mapping e accesso RW distinti.
Growth/release hanno fence esplicito; `cuMemUnmap` tratta interi segmenti.
Due segmenti per buffer, 121 slot da 72 B, owner 50.848 B. Il driver deve
supportare VMM e granularità potenza di due ≤2 MiB; assenza o errore è
terminale, senza fallback. Non c’è nuovo lemma Lean di raffinamento CUDA.

Preflight: 22 scenari simulati passano, inclusi confronto A bit per bit
con backing completo, tre append KV, duplicato, upload vietato e fault di
capability, granularity, reserve, allocation, mapping, accesso, budget,
fence, unmap e release. Le regressioni C++ default e pool passano (quattro
pytest, 41,92 s, un worker/AS 2 GiB/60 s); il test Rust dei KV condivisi
passa in 17,16 s. Build Rust finale 58,077 s, RSS aggregato osservato
2.614.669.312 B, entro 3 GiB/120 s. Il primo preflight aveva sovrapposto
per errore test e compilazione in due processi limitati separatamente;
la build finale e le regressioni sopra sono state eseguite separatamente.
Un launcher dei test C++ con nome file errato non ha avviato test ed è
conservato insieme al retry corretto. Non sono risultati di GPU.

Lo screen di contabilità conserva il costo pieno arrotondato del KV fuori
dalle sole fasi iniziali A O=0, così non attribuisce benefici alle fasi
non misurate. Richiede un nuovo receipt della granularità e rifiuta la
combinazione con il pool sperimentale. Le riserve di arena/payload/fisico
restano invariate. Nessuna selezione canonica, root completa o certificato.

I due nuovi simboli obbligatori rifiutano librerie incomplete (21,20 s);
la parità Rust delle root A, aperture e istogramma passa in 22,89 s.
Dieci test del ledger passano; gli screen tengono distinti 64 KiB e 2 MiB.
I log preliminari, compresi il filtro Rust iniziale senza match e i
launcher falliti, sono in
`artifact/c7.1-pod/certificates-vmm-local-20261011T105000Z`, manifest SHA-256
`e4ef768fdfb76851b1c1091c3d68f6a4572f7325f85a5a102d3e316049352b56`.
Sono verifiche con working tree modificato; un record pulito successivo
è necessario per la misura di riferimento.
