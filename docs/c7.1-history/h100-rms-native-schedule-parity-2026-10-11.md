# RMS GPU — calendario implementato verificato

Checkout pulito `4f0ec2c25a25f2b1ec5b01ca473857bae4a9a057`, solo CPU
sul pod H100 autorizzato, AS64 GiB/un worker. Il
[record](../../benchmarks/results/c71-certificates-rms-native-schedule-2026-10-11-4f0ec2c2.json)
SHA-256 `e1cfc14aff14c3c5a2a01913871209261da2804a3852dedffc3664b76c1a74c8`
conserva40 raw, archivio127.557 B, manifest/hash verificati in streaming.
Sette controlli del conto e nove documentali passano; due screen CPU
completi. Il calendario riproduce esattamente7.830 launch dell'oracolo
denso originale e787.599 del [trial misto159/99](h100-rms-mixed-all-parity-2026-10-11.md).

Il [primo negativo](../../benchmarks/results/c71-certificates-rms-native-schedule-negative-2026-10-11-4f0ec2c2.json)
conserva7 test passati e un controllo documentale fallito per fonti
storiche ignored assenti nel nuovo worktree (otto altri test passati).
Le medesime fonti Markdown immutabili del checkout principale sono
esposte via symlink, con ricevuta/hash; nessun download, conversione o
modifica degli originali. Trial nuovo, senza riprendere lo stato fallito.

Sul supporto originale2^29 celle/347.937.024 vive,159 programmi e99
profondità, il runtime attuale richiede analiticamente:

| Finestra sorgente | Coppie tail | Launch cella/indici | Posizioni padded lette dal tail |
|---|---|---|---|
|256|16|182.626.739.937|1.328.755.507.200|
|4096|256|11.418.407.370|1.328.755.507.200|

La maggiore finestra modifica il batching, non le25 riletture per
profondità. Sono conteggi del codice attuale, non launch eseguite in
dominio canonico o traffico HBM misurato. Nessun tempo dedotto dal trial
ridotto. Capacità private parziali indice/fold non sono il conto completo.
Lo screen256 ha un campione incompleto: nessun credito al picco stabile.
GPU zero nei campioni; VM solo editing/controllo/verifica artefatti.

Questo esito chiude la diagnosi del calendario, non il costo completo:
serve ridurre launch e replay prima di un'ammissione del runner canonico.
Byte/statistica GPU, checkpoint/host/device simultanei, allowance driver,
modello/PCS/real-AES e raffinamento formale aperti. `credit:false`,
`complete_work:false`, `complete_capacity:false`, `joint_admitted:false`.
Zero certificati; pod e guard conservano la finestra originale.
