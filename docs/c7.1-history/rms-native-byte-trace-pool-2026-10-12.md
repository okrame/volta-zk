# RMS byte GPU — trace verificata, aspettativa pool da correggere

Il [trial pulito ccadf8f9](../../benchmarks/results/c71-certificates-rms-native-byte-trace-pool-negative-2026-10-12-ccadf8f9.json)
passa i quattro test trace: lifecycle, logger/cleanup con fault, header e
physical. Dimensioni42.536/42.544B confermate;60,430s, massimo fisico
campionato395.739.136B, GPU0, zero campioni incompleti. Nessun credito
al picco istantaneo o matematica CUDA. Owner byte/indici/generico invariati
e già verificati su fca43aef, ricevuta di riuso esplicita.

Il test pool compila ma si ferma sull’aspettativa vecchia42.568B nel
fixture C++; anche la successiva assertion Python contieneva quel valore.
La correzione aggiunge gli8B del puntatore byte, nuova aspettativa42.576B
da verificare. Negativo15,809s, fisico392.605.696B, GPU0, zero incompleti.
Sono preservati archivio, manifest e tutti i log prima del nuovo trial.

Ricerca completa delle assertion di owner nel codice/test: solo queste
due erano ancora legate al vecchio layout. I marker del ledger sono
fixture storiche/sintetiche e rimangono immutati. Pool/tail, CUDA/Rust e
aritmetica byte GPU ancora pendenti; stessi cap e deadline autorizzata.
Zero certificati canonici, nessuna nuova sessione AES o selezione canonica.
