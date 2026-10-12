# Nuovo pod, limite tre ore e canonico con P0 per righe

Il proprietario autorizza il nuovo `wgteo4z5mndiof` e chiede di finire
entro tre ore. REST data l’avvio al12 ottobre13:43:08.832 UTC: compute
end16:13:08.832, guard16:33:08.832, hard stop16:43:08.832. La riserva di
chiusura è30min, inclusa nella durata. La nuova decisione sostituisce
l’indisponibilità del precedente pod, senza importarne lo stato.

L’accesso proxy fornito dal proprietario funziona con la chiave già
presente nella VM; il percorso `~/.ssh/id_ed25519` indicato non esiste
nella VM. Il proxy autenticato e l’accesso diretto concordano sulla chiave
host e sul container176a9733c854. H10080GB HBM3, UUID
GPU-fb0e2f6f-ffd0-356f-d12b-cb2bff004319,81559 MiB; cgroup memoria
250.999.996.416 B. Il guard indipendente123071 è vivo nel contesto host
con startticks339841187. Compilazioni, test e modello restano sul pod.

Il [record di avvio](../../benchmarks/results/c71-certificates-newpod-start-2026-10-12-62f97a7a.json),
SHA256 `ef850528fca01400980e20b3b9df665f0d5c93d85809b5f6d7cef8d38dfd6917`,
conserva i due negativi di preparazione: GNU time assente nel primo
tentativo e directory weights precreata nel secondo. Risolti installando
la dipendenza e correggendo il solo launcher; directory/evidenze nuove,
nessun setup crittografico avviato nei tentativi falliti. Input Γ pubblici
originali trasferiti e hash verificati:9 file/34.826.344 B, nessuna
ricalibrazione. Shard pinned e ingest completo coincidono con il pack
originale61.394.690.560 B/hash1a88da14…; modello03 pronto alle14:10:04 UTC.

Il [preflight e avvio canonico](../../benchmarks/results/c71-certificates-newpod-preflight-start-2026-10-12-62f97a7a.json),
SHA256 `800ee04759bd8a03de2f330d43763e828c9f3d05fc98345ee0c85ae72bcbc3c3`,
passa18 controlli sul checkout pulito62f97a7a. La candidata P0 per righe
ead7bb43 passa la fixture ragged originale:6 caricamenti riga A,5 W,
stessi valori/padding e rifiuti. Passano P0/MAC originali, radici e tied
head in W, caller RMS CPU, statistica GPU24 coefficienti/3 terminali e
caller shared statistica+byte con wire/FS/MAC originali e alterazioni
respinte. Quattro controlli CUDA canonici, owner VMM/pool e runner passano.
I test Rust eseguono un caso ciascuno; nessun filtro vuoto. Le misure di
componenti non dimostrano un miglioramento temporale canonico.

La sessione completa `canonical03` parte alle14:10:05.988 UTC con codice
62f97a7a pulito, real/AES fresco, KV vuoto e journal nuovi. PID effettivo
18200/startticks1777845271, timeout7362s prima della riserva di chiusura.
W è installato e il setup AES inizia al progress elapsed301,684s;
nessun certificato o accettazione finale a questo checkpoint. O=150/300
seguono soltanto l’accettazione originale del contesto precedente.

Il watcher iniziale che osservava il launcher è sostituito da un client
che osserva il PID effettivo; nessun processo della prova è riavviato.
Il salvataggio accettato richiede BLAKE3 del body, C71ACC01 positivo,
fase prover dopo fsync/promozione e receipt uguale nei due journal.
Il controllo hash readonly passa la fixture abc, senza credito di prova.
Rimangono aperti picco fisico simultaneo, raffinamento CUDA/NoPeek e
gli altri limiti già dichiarati nel design; cap e verificatore invariati.

Rettifica della precedente osservazione di processo: il guard94185 del
vecchio pod era vivo nel contesto host, anche dopo13:39 UTC. Il `/proc`
del sandbox locale non lo esponeva; la precedente deduzione di assenza
è ritirata. Il pod precedente resta assente dal provider e la causa
riportata dal proprietario resta credito esaurito. Il guard vecchio è
ritirato soltanto dopo nuova risposta `pod:null` e verifica PID/startticks;
ricevuta privata `certificates-oldguard-visibility-correction-20261012`,
manifest SHA256 `10a04a7cdde7723e0c5f68722a29eff7251f502c0ae8bb7f106b79e8fae98503`.
Record e manifest precedenti rimangono immutati.
