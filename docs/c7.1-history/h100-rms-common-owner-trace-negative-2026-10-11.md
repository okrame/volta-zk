# RMS: primo pass dell’owner e negativo diagnostico

Il [trial pulito `a324ebf3`](../../benchmarks/results/c71-certificates-rms-common-prefix-negative-2026-10-11-a324ebf3.json)
termina alle19:37:34 UTC: i tre test dell’owner comune passano,
inclusi19 rifiuti RMS, copertura, errore di copia/fence/free e pubblicazione
successiva al rilascio. Driver simulato, nessun calcolo GPU.
Default42.280 B osservato. Due dei quattro test di traccia falliscono
per valori attesi della vecchia dimensione:42136/42128 contro42320/42312 B.
La modifica a184 B dello stato RMS richiede l’aggiornamento dei controlli
che misurano l’owner corrente; marker di ledger ed evidenze storiche
rimangono invariati. La variante pool corrente attende42352 B.

Il negativo è conservato in27 file/79.679 B con monitor e hash. Non è
stata avviata la build Rust o la prova GPU. Prima del nuovo trial si
correggono tutte le attese correnti collegate e si aggiungono controlli
Rust per lunghezze, owner/capability e simboli obbligatori RMS.
Stesso pod e deadline originale; zero certificati canonici.
