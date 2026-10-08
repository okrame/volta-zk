# Decisioni operative — 8 ottobre 2026

Il proprietario ha approvato queste decisioni nella conversazione del task
di pulizia documentale. La formulazione operativa è nel
[runbook attivo](../c7.1/runpod-tests.md#autorizzazione-e-limiti);
questa nota conserva motivazione e provenienza, senza autorizzare hardware.

| Decisione | Motivo e applicazione |
|---|---|
| Archiviare le campagne concluse | Pod, orari, proroghe, stime e autorizzazioni passate non devono sembrare istruzioni per il prossimo agent. I cinque documenti attivi conservano risultati attuali e link |
| Durata propria di ogni campagna | Le sei ore e la riserva della campagna precedente non diventano un default. L'istruzione corrente fissa durata, hardware, ambito e riserva di chiusura |
| Limiti AS distinti | Locale 60 s / 2 GiB; CPU RunPod AS 64 GiB; CUDA senza cap AS, con monitoraggio e arresto per limiti fisici, arena e deadline. Non occorre rinnovare l'eccezione CUDA |
| Trial entro la campagna autorizzata | Correzioni e nuovi trial sono inclusi nello stesso ambito e termine; nuovi file, journal, KV vuoto e correlazioni fresche. Nessuna ripresa del run fallito |
| Ritenzione selettiva | Il proprietario richiede di rimuovere artefatti vecchi non più necessari da `artifact/c7.1-pod`; restano input di Γ, provenienza ed evidenze uniche. Il tetto cumulativo resta 10 GB |
| Geometrie ottimizzabili | Quattro coset e 1.024/512 scansioni descrivono l'implementazione corrente. Alternative richiedono equivalenza verificata e conto completo; sicurezza, protocollo e risorse restano vincolanti |
| Push preautorizzati | Codice ed evidenze pubblicabili su branch dedicato, via Git HTTPS, senza nuova conferma per commit; revisione dei contenuti, niente segreti/valori privati, force-push o merge impliciti |
| Calibrazione condizionale | Il percorso principale riusa Γ già ammesso dopo verifica delle identità e dell'impatto delle modifiche; ricalibrare quando l'ammissione pertinente viene invalidata |

## Evidenze e archiviazione

Γ è ammesso dal [record del 7 ottobre](../../benchmarks/results/c71-gamma-admission-2026-10-07-868a3e8.json).
La [diagnostica](../../benchmarks/results/c71-cuda-experiment-2026-10-07-868a3e8.json)
resta incompleta nel commitment W; ottimizzare l'installazione e la prova
non richiede ripetere automaticamente una calibrazione valida.

Le versioni precedenti di [design](design-2026-10-07.md) e
[runbook](runpod-tests-2026-10-07.md) conservano cronache, tentativi,
stime e autorizzazioni superate. I link ai documenti attivi sono adattati;
la fonte Git e il digest originale sono dichiarati in ciascun archivio.
La [pulizia degli artefatti](artifact-retention-2026-10-08.md) registra
le rimozioni e le verifiche eseguite, senza riscrivere i manifest originali.
