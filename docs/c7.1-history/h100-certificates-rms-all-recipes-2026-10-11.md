# C7.1 — RMS su tutte le ricette, 11 ottobre 2026

Il [record pulito](../../benchmarks/results/c71-certificates-rms-all-recipes-2026-10-11-04137d0c.json)
conserva due esecuzioni CPU della fixture con **159 ricette originali,
99 profondità, 511 celle vive e una di padding**. Ogni riga sintetica
non nulla è calcolata da `Integer::row`; prover e verifier GKR originali
completano, con stesso punto/FS fra i due ruoli, endpoint MAC valido e
consumo di tutte le correlazioni ideali. I limiti erano 600 s per processo,
AS 64 GiB, un thread di test e cap fisico 6.174.015.488 B. Nessun timeout,
errore o swap; GPU idle prima di ciascun processo e dopo il workflow.

La baseline usa la SHA pulita `7dc4d2be95cb43435c168a7fc207121a3ccdf23c`;
la candidata a tre prodotti usa `04137d0c5595ea53d3c82ecd5ca0dd64672efdee`.
Entrambe includono il replay packed e i pesi Eq incrementali. I binari sono
conservati separatamente con hash, comandi e toolchain. La compilazione
baseline/candidata richiede 594,599/457,233 s; RSS massimo aggregato
2.922.299.392/2.926.641.152 B. Le build CPU si sovrappongono al trial A;
le misure GKR iniziano dopo la sua chiusura e non includono compilazione Rust.

| Misura | Baseline | Tre prodotti |
|---|---:|---:|
| Compilazione dei 159 circuiti | 2,555403369 s | 2,673374269 s |
| Prover completo della fixture | 194,165777463 s | 191,237654814 s |
| Verifier della fixture | 6,576525668 s | 6,602378559 s |
| Processo monitorato completo | 203,696112290 s | 200,934104515 s |
| Prodotti Fp3 del core coefficienti | 1.321.999.818 | 1.176.979.554 |
| Callback del checkpoint nei cell round | 455.301 | 455.301 |
| Wire serializzata | 320.320 B | 320.320 B |
| Correlazioni ideali consumate | 9.919 | 9.919 |
| Massimo RSS campionato | 734.949.376 B | 734.371.840 B |
| Massimo fisico con GPU intera | 734.949.376 B | 1.218.600.960 B |

Il rapporto dei tempi prover è 0,9849194709: **−1,51% osservato in una sola
coppia**, senza conclusione statistica. Le 99 profondità sono effettivamente
eseguite in entrambe le prove. La wire ha la stessa lunghezza, ma il test
non ne esporta byte/hash per un confronto incrociato fra binari; la parità
byte-per-byte resta quella della fixture mista locale distinta. Il record
contiene i contatori completi nei log privati, non una stima del tempo canonico.

Durante la candidata, 15/999 campioni tra epoch `1791722704.1060367` e
`1791722707.3700476` rilevano memoria GPU non nulla, massimo 556.793.856 B.
L’origine non è attribuibile: il monitor conserva memoria dell’intero
device ma non un inventario contemporaneo dei processi CUDA. La fixture
non invoca il backend CUDA. Il successivo controllo non trova processi
GPU; il workflow registra 0 MiB al termine. Questa occupazione resta nel
massimo fisico e impedisce di presentare la coppia come hardware isolato.
Nessun cap è stato aumentato e nessun campione è stato sottratto.

Bundle privato:
`artifact/c7.1-pod/certificates-rms-all-benchmark01-20261011T130000Z`,
53 file, 75.700.612 B; manifest SHA-256
`fbaa76fcbc5ca181460a846412fb631efbbaa466fe5fc0e348bb288c43fcf1e2`.
Le etichette dei percorsi non sostituiscono i timestamp effettivi.

Questa è una misura completa della **fixture RMS ridotta**, con tutti i
programmi originali. Restano esclusi statistiche del caller, modello reale,
PCS, AES e certificato di risposta. Il conto canonico corrente resta
751.359.028.655.932 prodotti Fp3 del core e 998.927.195.904 callback per
risposta; questi conti non sono tempi misurati. La riscrittura esatta non
risolve l’ostacolo RMS completo e non giustifica da sola un nuovo setup
costoso. Γ, relazione, field, messaggi e premesse formali restano invariati.
**Zero certificati canonici generati o verificati.**
