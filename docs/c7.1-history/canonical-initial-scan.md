# Scanner A e commitment iniziale — 3 ottobre 2026

Checkpoint locale successivo alla
[strumentazione del runner](canonical-runner-measurements.md).
Le istruzioni correnti sono nei [cinque documenti attivi](../c7.1/design.md).
Non modifica protocollo, autorizzazioni, bound Seed6 o obiettivi di risorse.
Il [record sulla SHA pulita 83d366c](../../benchmarks/results/c71-initial-scan-local-2026-10-03-83d366ccbc5c.json)
conserva 23 test Rust, 9 controlli documentali, due rifiuti CLI, build e
lint. Conserva separatamente la regressione di sviluppo del cap query:
l'aumento iniziale ammetteva oltre 1.024 righe anche nei domini piccoli;
la policy condivisa ora mantiene quel rifiuto. Tutti i controlli della
revisione pulita passano, con `credit:false` e `readiness:false`.

Il precedente commitment richiamava il getter scalare di ogni coefficiente;
per A questo selezionava finestre da 128 byte e ripeteva la ricostruzione
dei produttori. Inoltre il cap Merkle 2^18 respingeva W/D35 e A/D34.
La nuova route riusa lo scanner causale esistente e accumula ogni sorgente
direttamente nel coset. Il callback emette indici originali, non richiede
ordine piatto e non riceve monete PCS. Una bitmap per righe respinge
omissioni/duplicazioni; l'indice delle tessere per sorgente evita di
riscandire tutto il layout per ogni riga. Gli errori del consumer si
propagano al primo byte.

Il commitment iniziale ammette soltanto la geometria grande scelta:
128 colonne base, coset 2^22, taglio Merkle 2^12. A ha altezza 2^31 e
512 scansioni; W ha altezza 2^32 e 1.024 scansioni del packed. Le altre
geometrie grandi falliscono prima di allocare o consumare sali. Non viene
riammesso il piano A a 1.024 ricostruzioni escluso storicamente. Hash
salato, seek e riuso delle celle consumate sono quelli del replay esistente.

Il coset base ora usa un solo buffer column-major e una colonna FFT
riutilizzabile, eliminando le copie complete row-major/column-major.
Entrambi i twiddle P3 restano vivi fra coset. Le potenze fattorizzate
consentono lo scatter non monotono e mantengono i pad alle posizioni
originali, anche se il prefisso vivo termina prima. Bitmap, potenze,
metadata, colonna FFT e due twiddle non sono inclusi automaticamente
nel vecchio subtotal Merkle: il picco simultaneo completo resta aperto.
Nessuna liberazione GPU è dedotta da scope Rust o `truncate`.

I controlli ridotti aggiunti coprono 512 scansioni D14 senza accessi al
getter scalare durante il commit, root contro un commitment nativo denso
indipendente, aperture con duplicati e monete fissate, posizioni dei pad,
ordine di emissione invertito/interlacciato ed errori dello scanner.
La geometria canonica è controllata senza allocare domini grandi.
Il fixture di un operatore softmax canonico controlla emissioni di
checkpoint, istogramma e padding interno; una piccola partizione ragged
i16/i32/i48 confronta ogni byte con il mapping packed indipendente.
Sono controlli componenti, non inferenza o certificati Gemma completi.

Restano locali: query/range in finestre previste, stato sourcewise oltre
D16 e P/Q canonico, stadi extension grandi con S1/S2, kernel densi GKR e
verificatore, CUDA esatto e contabilità simultanea di tutti gli owner,
separazione inferenza/prova e composizione canonica positiva. Il getter
scalare è ancora usato fuori dal commitment iniziale. Il nuovo cap query
2^21 non dimostra il picco delle strutture intermedie del resto CPU.
Non sono stati eseguiti domini D34/D35, scaricati pesi, usate GPU o creati
pod. Certificati canonici acquisiti: zero. Il superamento analitico dei
40 MB nelle continuazioni rimane; la composizione Seed6 resta condizionale
con gli obblighi descritti nella sicurezza attiva. L'hard stop provider
richiede sempre deadline verificabile o controllo di spesa autorizzato.
