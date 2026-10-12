# Nuovo pod — setup AES e inferenza O=0 completi, A47/512

Il [checkpoint immutabile](../../benchmarks/results/c71-certificates-newpod-inference-checkpoint-2026-10-12-62f97a7a.json)
ha SHA256 `c26eb833bd4be7969aaf4205ce13b60942a894b0eefe99547bd6094d8eb93980`.
Proviene dalla stessa sessione reale `canonical03` sul pod wgteo4z5mndiof,
codice pulito62f97a7a, PID18200/startticks1777845271. Nessun riavvio o
import di stato dopo l’avvio14:10:05 UTC.

Setup Seed6 reale/AES completo: verifier1489,593009546s e
prover1489,593514509s. Preparazione con inferenza O=0 completa79,114723220s;
non è un tempo d’inferenza isolata. Il log registra anche W load55,587279018s
e commitment/installazione W211,582453323s; confronto non accoppiato con
altre campagne, nessuna attribuzione del guadagno alla candidata P0.

Alla sequence624, elapsed2194,754992608s, il commitment A ha completato
47/512 gruppi. Owner51.288 B, arena live4.136.488.704 B e peak capacity
5.189.054.976 B nel contatore nativo, W escluso61.394.690.560 B. Cleanup
failed0 e stopped0 a quel campione; nessun picco fisico completo dedotto.
Il checkpoint conserva tutti i14 phase end del runner disponibili e
la provenienza/hash della nuova osservazione, senza modificare i precedenti.

**Zero certificati canonici a questo checkpoint.** A non è ancora completo;
corpo prova, acceptance originale e journal durevoli restano da ottenere.
O=150/300 seguono solo l’accettazione del contesto precedente nella stessa
sessione. Compute end16:13:08.832 UTC, hard stop16:43:08.832 nella finestra
originale di tre ore, inclusa riserva30min; cap e ambito invariati.
