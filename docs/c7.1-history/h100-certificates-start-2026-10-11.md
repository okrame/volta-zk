# C7.1 — avvio della campagna certificati, 11 ottobre 2026

L’allegato del proprietario autorizza otto ore sul solo pod
`z6wx2kkn69eoc0`, inclusi trenta minuti di conservazione e spegnimento.
Base verificata pulita `3a8d004dc1ef4fbdd426f3b8cfc2c325bdd0c9ac`,
nessun commit successivo locale. Branch nuovo
`runpod/z6wx2kkn69eoc0/c71-certificates-20261011`, pubblicazione Git HTTPS.
La campagna precedente è [chiusa](h100-followup-close-2026-10-10.md).

Il provider era già RUNNING alla prima query: uptime 289 s. Il guard
ricostruisce l’avvio come istante precedente alla query meno uptime e
sessanta secondi: **07:31:18,237 UTC**. Fine calcolo **15:01:18,237 UTC**,
guard **15:26:18,237 UTC**, stop provider entro **15:31:18,237 UTC**.
Il nuovo guard indipendente della VM, PID 4147417, ha confermato readiness;
nessuna deadline della campagna chiusa viene riusata. Query, deadline e
ricevuta sono conservate nel bundle privato
`artifact/c7.1-pod/certificates-start-20261011T074100Z/`.

SSH sul nuovo endpoint provider verifica NVIDIA H100 80GB HBM3,
81.559 MiB, UUID `GPU-e05e977b-758d-f3f4-cbe8-5720b83d1ae1`, zero
memoria GPU usata e nessun processo compute. La chiave indicata
`~/.ssh/id_ed25519` è assente sulla VM; la chiave locale già disponibile
consente l’accesso allo stesso pod. Il proxy richiede PTY; l’endpoint
diretto provider è accessibile. Il container è nuovo, `/workspace` vuoto,
230 GiB disponibili: occorre ripristinare codice e input verificati.
Il preflight Git HTTPS VM passa sulla SHA base pulita; nessuna credenziale
viene trasferita al pod. Il percorso harness provider fallisce per CLI
assente; le API già usate e autorizzate forniscono controllo e stop.

Obiettivo minimo: corpo canonico completo O=0 conservato immediatamente,
con hash, dimensione, provenienza e verifica designata registrata nel
journal durevole. Obiettivo completo: O=0/150/300 nella stessa sessione.
Il runner attuale non esporta il corpo: implementare l’export prima dei
trial completi. Commitment A, prefissi o ricevute da soli non bastano.

Prima del setup completo affrontare spike fisico A e costo RMS/GKR
rappresentativo. Nessuna ripetizione Nsight invariata; nessun confronto
floating o nuova calibrazione. Γ ammesso e input necessari sono riusati
previa verifica pertinente. Pool/fill, semantica intera, geometria PCS,
NoPeek, MAC originali, PCG AES reale e correlazioni monouso restano fissi.
Ogni nuovo trial parte da O=0, journal nuovo, KV vuoto; nessun resume.

Restano i cap originali: payload 5.905.580.032 B, fisico 6.174.015.488 B,
margine arena 256 MiB, globale almeno 1 GiB; CPU AS 64 GiB, soli figli
CUDA senza cap AS. Timeout finiti, teardown seguito da GPU idle, bundle
persistente cumulativo massimo 10 GB. Il target 65 s è distinto dal
completamento: conservare tempi reali anche oltre target. Premesse Seed6,
raffinamento Rust/CUDA e allowance restano aperte; zero certificati ad avvio.
