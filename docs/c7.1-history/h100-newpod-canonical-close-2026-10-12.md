# Nuovo pod — timeout nel corpo prova, zero certificati e provider chiuso

Il [record terminale immutabile](../../benchmarks/results/c71-certificates-newpod-terminal-close-2026-10-12-62f97a7a.json)
ha SHA256 `a0f9bd98dd71fbd36f660968ab1f60be56a4f98ac6d0b762c6814608f2a1a2de`.
La sessione `canonical03` sul codice pulito62f97a7a termina per il timeout
di7362s: monitor exit−9, wrapper247, `TimeoutError: phase or authorized
compute deadline reached`. Il limite scade alle16:12:48 UTC, prima della
riserva di chiusura. Il processo era attivo e usava CPU sino allo stop.

Sono completi setup reale/AES, preparazione con inferenza O=0 e A512/512;
il corpo prova resta incompleto dopo almeno2023,678s. **Zero certificati
completi generati e zero accettazioni canoniche verificate.** O=150/300
non sono iniziati. Nessun response/acceptance nel bundle terminale; journal
P218 B con record setup/burn, V161 B con solo setup, nessun record acceptance.
Il timeout non è un rifiuto del verificatore o una prova completa.

Il watcher terminale conserva26 file/16.166.578 B: stdout/stderr, memoria,
progress completo, owner trace, due journal, provenienza e teardown GPU.
Tutti gli hash sono riverificati. Stderr vuoto; payload osservato massimo
5.514.137.127 B, temporaneo stabile campionato5.994.638.848 B,36.744
campioni, zero incompleti/smaps failure. Il picco fisico istantaneo e la
sufficienza del margine runtime restano non dimostrati; niente credito
al target, alla sicurezza completa o al tempo canonico da questi campioni.

PID18200 e launcher7020 risultano assenti al controllo terminale.
GPU idle, nessuna compute app e uso0 MiB alle16:12:50 UTC. Provider
**EXITED/runtime assente alle16:15:46 UTC**, prima del massimo16:43:08
nella finestra di tre ore. Guard123071 ritirato soltanto dopo conferma
provider e verifica PID/startticks; i due watcher terminano normalmente.
Ricevute di chiusura in `certificates-newpod-close-20261012`; evidenze
precedenti e manifest invariati. La VM esegue soltanto controlli leggeri.

La correzione P0 per righe rimane validata dai18 check del preflight,
ma questo run non misura un corpo prova completo o un guadagno canonico.
Manca una localizzazione più fine del costo nel body; la sola attività
CPU non ne identifica tutto il lavoro. La nuova sessione completa O=0→150→300
richiede hardware/tempo disponibili e autorizzati, KV vuoto, AES/correlazioni
nuove e journal nuovi. Stato terminale e correlazioni bruciate non si riusano.
Il goal originale resta **non raggiunto**; nessun riavvio o tempo aggiuntivo
è autorizzato implicitamente dalla chiusura o dalle continuazioni del goal.
