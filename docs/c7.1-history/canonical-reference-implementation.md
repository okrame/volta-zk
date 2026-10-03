# Implementazione del riferimento canonico CPU — 3 ottobre 2026

Questo documento conserva decisioni ed evidenze del checkpoint; le istruzioni
correnti sono nei [cinque documenti attivi](../c7.1/design.md).
Il punto di partenza è il
[readiness audit v6](../../benchmarks/results/c71-h100-e2e-readiness-2026-10-03-fbd6141e7a1e.json).

## Decisioni implementate

Il corpo del prover riusa gli operatori del verificatore canonico, con lo
stesso ordine dei frame, un solo transcript e i batch originali di W,
A corrente e A precedenti. Non introduce nuove autenticazioni degli
endpoint intermedi. La riserva è controllata prima dei callback privati
e deve essere consumata esattamente.

Il getter riusa il driver numerico della calibrazione. Cattura i 61
checkpoint di layer, conserva KV e istogrammi e ricostruisce le righe
necessarie in ordine causale. La generazione di checkpoint è unica fra
le risposte; ricostruire una generazione storica richiede l'uguaglianza
di token, KV e digest. Il test sul padding distingue D/E interni dalla
coda esterna nulla del dominio PCS. Non è una prova sul modello intero.

Il completamento è un record di 73 byte legato al certificato pendente
e alla ricevuta FS. Non contiene storia importabile. Entrambi i ruoli
promuovono soltanto dopo il rispettivo journal. Il record richiede un
canale autenticato: l'hash non sostituisce tale premessa.

Il riferimento eseguibile usa socketpair locali, Seed6 reale ell=11,
gli input canonici della calibrazione e tre tentativi sullo stesso registro.
È esplicitamente CPU e non viene avviato sulla VM. I contatori riguardano
i canali effettivi e il massimo RSS host del processo, non il picco HBM,
la distribuzione fuori canale dei parametri o la contabilità fisica completa.

Nel riferimento ridotto si conservano i dati e i pad del commitment
iniziale denso, eliminando la loro ricostruzione a ogni apertura senza
cambiare domini, parametri crittografici o polinomi.

## Confine del risultato

Non sono stati letti o scaricati pesi reali, creati pod, avviate GPU o
sostenute spese. Non è stato verificato alcun certificato canonico.
I test ridotti e le fixture non conferiscono readiness.

Rimangono lavoro locale sul piano a 512 ricostruzioni, sui kernel che
materializzano vettori troppo grandi, sul collegamento CUDA e sul conto
simultaneo completo. Procurare H100 o pesi non implementa queste parti.
Γ reale, convalida dei certificati canonici, parità e misure GPU richiedono
inoltre i dati/hardware autorizzati. L'hard stop RunPod resta invariato.

## Fallimenti di sviluppo conservati

Prima del checkpoint pulito, una geometria Seed6 t=12/h=19/ell=2 è stata
rifiutata perché la capacità non era divisibile per tre. Il primo avvio
della geometria corretta t=8 è stato bloccato dal sandbox sulle socketpair;
l'eccezione successiva ha riguardato soltanto comunicazione locale.

Due prove ridotte a tre risposte, prima e dopo la conservazione dei
commitment iniziali, sono state fermate a 60 s dopo due accettazioni.
La seconda coincideva con una compilazione e non isola il tempo del test.
Entrambe rimangono esecuzioni incomplete, non evidenza di tre risposte.
Il test a tre risposte è conservato ma ignorato; il test distinto a due
risposte è passato entro il limite. Non è stata estesa la finestra CPU.
