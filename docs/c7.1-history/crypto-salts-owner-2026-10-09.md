# Sampler PCS nell'owner e Tree W/A — 9 ottobre 2026

Source `f85f6a77dbb2c7f0dcbb5297e74ec06cbcc67c51`, baseline `9033c64`.
Il [record pulito](../../benchmarks/results/c71-crypto-salts-owner-local-2026-10-09-f85f6a77dbb2.json)
ha SHA256 `4828e978ba8e9bba426d44ca64a0cf0496ef2b7f2e6332b812466a2949d50e5a`:
21 Rust e 11 Python positivi, 73 artefatti, albero pulito prima/dopo
ogni invocazione e digest binario invariato. Un controllo aggiuntivo CPU
lookup/GKR/WHIR termina exit124 a60s, dopo il log `initial_commit_A`;
non localizza ulteriormente la fase, non è un pass e non è stato ripetuto
o prolungato. Tutti i test AS2GiB/60s, un worker e processi seriali.
RSS massimo test/compilatori discendenti265.048.064 B; build completa
55,42s/2.483.286.016 B separata. Cargo pulito riusa lo stesso binario.
Nessuna compilazione o esecuzione CUDA/H100.

## Collegamento e invarianti

Il sampler originale conserva dominio34B incluso NUL, seed32, stream
LE, rejection Goldilocks e cap2^40. `with_private_rng` parte dal cursore
logico corrente; prescan device bounded fino2^24 candidati/chunk.
Dopo successo, `advance_to` avanza una sola volta e invalida il prefetch
host, mantenendo il buffer4096B per i draw successivi. Snapshot/seek,
clone MMCS e le aperture usano ancora il medesimo stream originale.

Sei simboli obbligatori ABI4 preparano/prescansionano gli indici, fanno
replay+hash W/A e controllano la copertura finale. `PrivateSalts` è opaco,
non clonabile, senza Debug/Serialize, legato all'owner Rust. Kind17 non
ammette allocazione, lettura/upload o rilascio pubblico. Seed, token e
puntatori privati non arrivano ai producer numerici; questi mantengono
buffer/layout/sink originali, senza FS, MAC o correlazioni. PCG AES reale,
correlazioni monouso, basi Fp3, parametri e identità Γ sono invariati.

Replay e hash condividono stream e flag sticky. Bande contigue fino65536
foglie, un controllo/fence hash per gruppo, nessun H2D sali o fence per
banda. Cursori finali e bytes consumati devono coincidere col prescan;
i digest non sono scaricabili fino al completamento e al ritiro dei
buffer privati. Free-failure conserva carica/ownership incerta e termina
l'owner; assenza di simboli e ogni errore restano terminali, senza fallback.
W seleziona32 coset/otto colonne/128 scansioni; A conserva quattro coset,
tutte128 colonne e512 ricostruzioni. Sono conteggi analitici sul pinned.

## Parità ed evidenza

Quattro fixture owner confrontano plain BLAKE3 Rust XOF/rejection,
starts/offsets/cursori e tutti i digest:512,256,131072,128 foglie, con
origine non allineata e consumo esatto fino al cap. La fixture131072
attraversa due bande con un solo fence hash, zero upload sali e picco
native14.713.344B; i valori delle128 colonne sono sintetici e caricati
solo nella fixture. Il prescan del driver è un oracolo sequenziale: non emula
o esegue la gerarchia CUDA. Tempi host non misurano GPU o throughput W.

31 rifiuti owner coprono errori di stream/fase/copertura, generic private
read/upload/release, owner estraneo, alias parziali/misallineamento/
overflow e token ritirato dopo un nuovo commitment. Sei simboli mancanti
sono rifiutati. I Tree W/A confrontano root/aperture/pad/istogramma/lavoro,
otto errori ciascuno; A mantiene64 ricostruzioni nella fixture D15.
Le prove composte confrontano wire, transcript, RNG e MAC originali;
tabella iniziale16MiB solo nel riferimento della fixture. Getter effettivo
verificato separatamente. D2H Tree W8996B e A8716B delta: comprendono
anche tutti i nuovi indici/contatori, senza valori originali numerici.
Picchi congiunti ridotti e tracce durevoli sono nel record.

Due esiti preliminari sono conservati: build E0282, risolta annotando
il Result; test W con aspettativa D2H vecchia4328B contro8996B effettivi,
risolto con il ledger completo. I test successivi di root/aperture e
prove composte passano. Il timeout CPU aggiuntivo resta negativo aperto.

## Conto delle risorse

Descriptor112B/progress40B/flag/counter sono compattati in metadata168B,
allineati256B e caricati una volta. Scratch prescan10.519.552B; con
starts/offsets/metadata27.297.024B W o23.102.720B A. Scratch e offset
device sono ritirati prima dei ring/valori; current8.388.608B e metadata
rimangono nel ledger hash. Banda device2.097.152B; banda host eliminata.
Owner host37.288B (+136), API Rust+48B, Stats152B invariato; tutto passa
dal contatore comune con capacità allineate e fail-closed.

| Screen | W | A |
|---|---:|---:|
| Fase device maggiore del componente | 3.745.182.208B | 4.751.622.656B hash |
| Fase device accumulo A | — | 4.650.965.536B |
| Host nominato | 87.195.304B | 47.749.512B |
| Con upper replay device785.789.696B | 4.618.167.208B | 5.585.161.864B |
| Payload residuo per altri owner host | 1.287.412.824B | 320.418.168B |
| D2H control minimo sali | 25.211.904B | 20.998.144B |

Il D2H include starts, offsets e current,44B per chunk prescan e8B per
gruppo completato; rejection può aggiungere chunk oltre i minimi1024/512.
H2D metadata168B per commitment; elimina analiticamente128/64GiB di
upload sali del precedente percorso host. Il lavoro XOF logico resta
almeno256/128GiB prescan+replay. Non sommare prescan ritirato e hash,
fasi alternative o picchi storici. Gli screen non ammettono il percorso
completo: altri owner host e picco fisico restano da verificare.

Il goal resta attivo. PCS A query/S1, aperture/closure GPU, GKR/range,
selezione QK/PV e sincronizzazioni/fusioni secondo profilo, risorse
simultanee complete e preparazione della campagna restano aperti.
H100 richiede nuova autorizzazione di hardware e durata; nessun run,
input Γ, benchmark o milestone congelato è stato sovrascritto.
