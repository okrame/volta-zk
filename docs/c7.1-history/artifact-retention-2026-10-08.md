# Ritenzione degli artefatti — 8 ottobre 2026

Pulizia autorizzata dal proprietario secondo le
[nuove regole](operating-rules-2026-10-08.md). Prima delle rimozioni sono
stati verificati 28 manifest sigillati e tutti i 950 file censiti.
I quattro file rimossi sono copie del codice o eseguibili superati;
nessun risultato grezzo unico è stato rimosso.

| File sotto `artifact/c7.1-pod/` | Byte rimossi | Provenienza conservata |
|---|---:|---|
| `first-failure-20261004T174606Z/code-d4abed66.bundle` | 48.546.485 | L'unico head del bundle, `d4abed66fc41d685889b8f54676390cba716a66c`, è antenato di `9033c64`; codice e storia restano in Git |
| `first-failure-20261004T174606Z/volta_pcs-c3c000ed1bc60c59` | 31.618.216 | Eseguibile di test superato; sorgenti, digest, comandi, build log e risultati originali conservati |
| `first-failure-20261004T174606Z/c71_calibration` | 4.154.464 | Binario superato; conservati quelli del pilot e del replay ammessi, oltre ai log e sorgenti originari |
| `kernels-20261007T130500Z/blocked-matrix-binary/c71_calibration` | 4.076.000 | Binario intermedio superato; sorgenti e risultati dello screen conservati |

Recuperati **88.395.165 B**. Dimensione logica della directory:
**185.513.494 → 97.121.061 B**, inclusa la nuova ricevuta di ritenzione.
Dopo la pulizia sono stati verificati nuovamente tutti i **946 file
originali conservati**. I 28 manifest originari e i loro sigilli sono
invariati: descrivono le esportazioni originali, non la ritenzione corrente.

La ricevuta privata sigillata è
`artifact/c7.1-pod/retention-20261008T080649Z/`:
`plan.json` contiene path, byte, SHA-256, digest del manifest originario,
motivo e provenienza; `result.json` registra l'esito. La pianificazione
è stata scritta e sincronizzata prima di ogni rimozione. Il riuso deve
consultare la ricevuta, distinguere i quattro ritiri intenzionali da
file mancanti inattesi e verificare tutti gli input effettivamente necessari.

Sono conservati la ricevuta Γ e il suo checker, candidata, entrambi i
replay, confronto indipendente, ledger/ricette, tabelle certificate e
binari richiesti dal checker. Rimane anche il binario della prova nel
bundle `first-failure`: il medesimo digest è stato usato nell'ultima
campagna. L'età o il nome di un bundle non bastano a renderlo eliminabile.

Dopo la pulizia il checker originale di ammissione è stato rieseguito
sui file conservati: tutti e cinque i controlli passano e la ricevuta
rigenerata in una directory temporanea coincide con quella originale.
