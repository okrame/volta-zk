# C7.1 — chiusura operativa prima della H100, 9 ottobre 2026

Questo checkpoint documenta le correzioni richieste dopo la revisione del
passaggio hardware. Le istruzioni correnti rimangono nei
[cinque documenti attivi](../c7.1/design.md).

## Esito e provenienza

Codice `24b54d4144211cec93c1847b84c0b5fe0a81b5c2`, baseline `9033c64`;
[record locale](../../benchmarks/results/c71-preh100-operational-local-2026-10-09-24b54d414421.json)
con albero pulito, digest del binario e 86 artefatti verificabili.
Passano 28 test Rust, 28 test del monitor e 9 controlli documentali,
in 25 invocazioni seriali. Nessuna nuova campagna è autorizzata.
La preparazione operativa locale è completa; esecuzione CUDA, cinque tempi
e ammissione fisica congiunta restano compiti della campagna autorizzata.

## Correzioni e loro ragione

- Quattordici ingressi hardware positivi ignorati riusano gli oracoli host;
  insieme al range preesistente sono 15 filtri distinti. La guard rifiuta
  libreria assente, percorso relativo e driver simulato anche rinominato.
  La riserva delle fixture ridotte è 256 B; il range da 512 MiB conserva
  256 MiB. Le catene D10 usano commitment iniziale CPU dichiarato; i
  commitment GPU sono confrontati separatamente D15. I test host passati
  non attribuiscono parità CUDA ai nuovi ingressi.
- Il timeout diagnostico read/write è finito e registrato, separato dal
  target di 65 s. Il monitor lo imposta alla durata del processo e applica
  deadline esterna e riserva di chiusura. Framing, verifica e terminalità
  rimangono invariati; timeout e disconnessione sono testati localmente.
- Il monitor distingue calibrazione e canonico, controlla memoria
  congiunta, HBM/margine, swap/OOM, disco e deadline, e arresta l'intera
  sessione, inclusi gruppi figli. Sottrae soltanto W residente dimostrabile:
  limite inferiore da `smaps` host e lifecycle device. Gli eventi precedono
  il primo touch host e coprono allocazioni device parzialmente fallite;
  i marker di ritiro seguono il rilascio degli owner. Dati mancanti fermano
  il run. I metadati CPU/GPU descrivono ora le route correnti.

I test del monitor emulano GPU, cgroup e GNU time; esercitano realmente
processi, sessioni, gruppi e un mapping host da 8 KiB. Il wrapper richiede
sul pod Linux `/proc`, cgroup v2, GNU time e `nvidia-smi`. I campioni di
transizione non attribuiscono credito congiunto; il picco fisico completo
rimane non misurato. Il monitor non sostituisce il guard di spegnimento pod.

## Risorse e limiti dell'evidenza

La build finale impiega 53,79 s, RSS aggregato campionato 2.603.102.208 B,
entro deadline 120 s e stop 3 GiB. I test usano un worker, AS 2 GiB e
60 s per invocazione: massimo 56,04 s e RSS 328.359.936 B. I wall dei test
comprendono la compilazione del driver simulato; non sono benchmark H100.

Il ledger rigenerato conserva 653 fasi e 11 classi. Il campo di lifecycle
aggiunge esattamente 8 B a ciascuna fase tramite la capacità tipata
`Arc<Mutex<Runtime>>`, senza addebito manuale duplicato. Massimo modellato
5.878.734.842 B, residuo 26.845.190 B sul payload 5.905.580.032 B.
Gli eventi nuovi rientrano nel bound JSON preesistente; la lettura di
`/proc/self/stat` usa 4 KiB di stack. Il monitor esterno è incluso nel
conto RSS fisico campionato, non nel census dell'allocatore Rust.
Rimangono le premesse path/argv ≤4.096 B, Γ/layout/toolchain e
`joint_admitted:false`; non è una dimostrazione del picco fisico.

Sono conservati due fallimenti preliminari delle fixture del monitor
(dipendenze cgroup/time assenti nella VM) e il rifiuto sandbox delle
socketpair Unix. Lo stesso binario passa i cinque test del runner con
l'eccezione locale documentata, senza rete esterna. La build preliminare
a tree dirty resta distinta dalla build finale; nessun record precedente
è stato sovrascritto.

Non cambiano Γ, kernel numerici, protocollo, NoPeek, MAC originali,
correlazioni monouso o PCG AES. Il precedente esperimento
[868a3e8](../../benchmarks/results/c71-cuda-experiment-2026-10-07-868a3e8.json)
resta incompleto nel commitment W. Nessun risultato qui dimostra il target
completo di 65 s, la compilazione sm_90 o le prestazioni della nuova GPU.
