# Nuovo pod — A512/512 completo, corpo prova avviato

Il [record immutabile](../../benchmarks/results/c71-certificates-newpod-A-complete-2026-10-12-62f97a7a.json)
ha SHA256 `3bf7ceced6c3924aa09f33991f81c625034b90fb3a402cd963af8b1c59b970f9`.
La stessa sessione reale/AES `canonical03` sul pod wgteo4z5mndiof, codice
pulito62f97a7a, completa A512/512 in3467,321826583s. Il progress conserva
tutti i boundary1..512 e il phase end originale `complete:true`.

Alla sequence4373/elapsed5338,326997516s inizia il corpo prova O=0;
PID18200/startticks1777845271 vivo al checkpoint. Il codice include i
getter P0 per righe validati nel preflight, senza modifiche al processo
avviato. Stesso W e Γ originali, nessun import KV/journal/correlazioni.

Il bundle privato `certificates-newpod-A-complete-20261012` conserva
osservazione/hash, phase end/resources e proof start. **Zero certificati
canonici verificati**: il commitment non è la risposta completa e manca
l’accettazione del verificatore originale. Nessun picco fisico completo
o guadagno temporale canonico dedotto. Il watcher conserva i certificati
appena completi e i due journal dopo acceptance durevole; il secondo
watcher conserva i log terminali senza modificare la prova.

O=150/300 seguono soltanto acceptance del contesto precedente. Compute
end16:13:08.832 UTC e hard stop16:43:08.832, entro le tre ore originali
inclusa riserva30min. Rimangono la prova completa e la verifica originale.
