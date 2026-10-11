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
