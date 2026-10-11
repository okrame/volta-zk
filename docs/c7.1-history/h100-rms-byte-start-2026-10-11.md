# Nuova campagna RMS byte e certificati — avvio 11 ottobre 2026

Il proprietario risponde alla richiesta di nuova durata con
`resume autorizzo a proseguire ssh z6wx2kkn69eoc0-64412195@ssh.runpod.io -i ~/.ssh/id_ed25519`.
È accettato il [piano preparato](h100-rms-byte-followup-plan-2026-10-11.md):
massimo otto ore complessive dall'avvio provider, inclusi trenta minuti
per conservazione e spegnimento, stesso pod e stessi cap/ambito.
L'obiettivo resta primo certificato canonico O=0 accettato durevolmente
dal DV originale e byte conservati immediatamente; poi O=150/300 nella
stessa nuova sessione. All'avvio: **zero certificati canonici**.

## Stato provider e deadline

Alla prima lettura il pod è già RUNNING. REST restituisce
`lastStartedAt = 2026-10-11 16:13:00.494 +0000 UTC` e
`lastStatusChange = Resumed by user: Sun Oct 11 2026 16:13:00 GMT+0000`.
L'uptime GraphQL da solo avrebbe datato l'avvio del container circa
27 secondi più tardi: non è usato per spostare l'avvio della campagna.

- Avvio provider: 11 ottobre **16:13:00.494 UTC**.
- Termine calcolo: 11 ottobre **23:43:00.494 UTC**.
- Stop del guard: 12 ottobre **00:03:00.494 UTC**.
- Limite assoluto: 12 ottobre **00:13:00.494 UTC**.

Identificatore `rms-byte03-20261011`, directory/sessione/guard nuovi.
Il guard indipendente parte con PID21664/start ticks332107132 e
conferma provider RUNNING. Un guard preliminare ancora più conservativo
è stato attivato prima della lettura REST, usando l'ultimo EXITED come
limite inferiore dell'avvio; è ritirato soltanto dopo la verifica del
nuovo guard vivo. Entrambe le ricevute sono preservate. Nessuna deadline
storica è ereditata e nessun comando resume aggiuntivo è eseguito.

## Identità e preparazione

Accesso tramite proxy SSH autenticato con host strict. Il path della
chiave indicato dal proprietario è assente sulla VM; si riusa la chiave
proprietario che ha già autenticato le campagne precedenti. Nessuna
chiave o credenziale della VM viene trasferita al pod.
Il proxy legge la nuova chiave host ed25519; l'accesso diretto usa il
known_hosts della campagna e la fingerprint verificata
`SHA256:HRZMN9Yu4939pFX7h+T2lGW12mTH+Djpli+AgeUBdfM`.

H100 80GB HBM3, UUID `GPU-e05e977b-758d-f3f4-cbe8-5720b83d1ae1`,
81.559 MiB, driver580.126.09; GPU0 MiB e nessun processo prima delle prove.
Il disco effimero contiene solo `.cache`: checkout/toolchain/binari sono
ricostruiti. Repository soltanto via Git HTTPS, credenziali sulla VM,
branch dedicato e checkout anonimo della SHA pubblicata pulita.

Il primo lavoro è il confronto AB/BA delle 159 ricette/99 profondità,
512 celle, cache16 MiB e gate condivisi comuni, byte contraction0/1,
600 s per prova. Fixture CPU AS64 GiB, monitor component senza esenzione W,
cap fisico6.174.015.488 B, un worker; nessun setup AES o profiler in questa
misura. I cronometri separano cella/replay, indici, byte e residuo.
Resta aperto il core RMS CUDA: misure ridotte e conti non sono un
certificato, tempo canonico o selezione delle candidate.

Il [record di avvio pulito `30867b9b`](../../benchmarks/results/c71-certificates-rms-byte-start-2026-10-11-30867b9b.json)
conserva timestamp REST, deadline, hardware autenticato e PID/start ticks
del workflow. Il bundle privato contiene19 file,30.284 B, manifest SHA256
`340d75461e565d2dd721b53fb8988a2093bb2f2738486f9a6ffe1393e7cc8a37`.
Il workflow parte alle16:22:50 UTC, PID1587/start ticks1476126403,
CPU AS64 GiB. Checkout anonimo pulito `30867b9b`, Rust1.96.1 e
ricette159 con SHA256
`b0c69fdb2395a1014f877725b119948af038a48baaebcbb4b336551f87f35853`
coincidente con la VM. Nove controlli documentali passano localmente,
AS2 GiB/60 s/un worker. Build e benchmark sono ancora in corso nel record:
nessuna misura completa RMS, nuova root o certificato viene attribuita.
Il controllo `/proc` sandbox non vede il PID del guard esterno; il
successivo controllo nel namespace host conferma PID21664/start ticks332107132
vivo. Non è una terminazione o un riavvio del guard.
