# Confronto RMS cache e gate condivisi — 11 ottobre 2026

Il seguito della campagna è concluso con **zero certificati canonici
generati o verificati**. O=0 resta incompleto; O=150/300 non sono iniziati.
Il provider conferma `EXITED` con `runtime:null` alle **14:27:28 UTC**.
Nessun nuovo setup AES o runner canonico è stato avviato. Γ originale
resta ammesso: nove file conservati, 34.826.344 B, sono stati riverificati.

Il [record immutabile](../../benchmarks/results/c71-certificates-rms-shared-cache-2026-10-11-bb7113ae.json)
ha SHA-256 `dce222962ffcffc249180bf30a53ecbb979515afd797cd104720df5fc7ea289c`.
Si collega ai [controlli locali del piano](local-rms-shared-gates-2026-10-11.md),
alla [cache folded](local-rms-fold-cache-2026-10-11.md) e alla
[prima chiusura della campagna](h100-certificates-close-2026-10-11.md).

## Ambito e provenienza

Stessa H100 UUID `GPU-e05e977b-758d-f3f4-cbe8-5720b83d1ae1`, stesso pod
`z6wx2kkn69eoc0`. Il riavvio provider delle 13:56:11 UTC non cambia
l'avvio conservativo 07:31:18, il termine di calcolo 15:01:18 o il limite
assoluto 15:31:18. Il guard aggiuntivo anticipava lo stop alle 14:39:15.
Lo stop effettivo arriva dopo 6 h 56 min 10,680 s dall'avvio originale,
includendo il periodo spento; 31 min 17,036 s dal riavvio. Il guard è
ritirato alle 14:27:38 solo dopo conferma provider, con PID/start ticks
e argv verificati. Non viene autorizzata ulteriore durata.

Il disco effimero è nuovo. La chiave SSH cambiata è stata verificata
tramite il proxy RunPod autenticato; il checkout anonimo Git HTTPS
usa `bb7113aeb184de057c8efe9e44ad4f88332601b4`, pulito prima e dopo.
Rust 1.96.1, opt-level 2, 64 codegen unit, un job e un worker.
Il binario conservato misura 35.945.080 B, SHA-256
`ac9b617f875ff0ebfd3b3fb428d5e1bea5826f9aa286486b2f075ea8809d6487`.

La build passa in 647,612 s entro il timeout 900 s. Monitor CPU AS
64 GiB e cap fisico 6.174.015.488 B; massimo RSS e fisico stabile
2.979.475.456 B, 3.232 campioni, zero letture smaps fallite.
Durante la build 18 campioni registrano occupazione GPU non attribuita,
massimo 556.793.856 B, dalle 14:15:04,209 alle 14:15:07,820 UTC.
Il codice del benchmark è CPU; manca un inventario contemporaneo dei
processi GPU e non si attribuisce la causa. GPU idle prima di ogni prova.

## Risultato misurato

Una coppia sequenziale sullo stesso binario: baseline senza candidati,
poi `C71_RMS_BENCH_SHARED_GATES=1` e cache 16 MiB. Ciascuna prova ha
timeout 600 s, AS 64 GiB e monitor dei cap originali. Tutte le 159
ricette Γ e 99 profondità, 511 celle sintetiche vive più una di padding.
Sono escluse statistiche del caller, modello reale, PCS, AES e risposta
completa; le correlazioni sono quelle ideali della fixture.

| Misura | Baseline | Gate condivisi + cache |
|---|---:|---:|
| Compilazione circuiti | 2,566 s | 2,574 s |
| Prover | 192,665 s | 158,589 s |
| Verifier | 6,568 s | 6,604 s |
| Wall monitor | 202,099 s | 168,282 s |
| Prodotti Fp3 del core di cella | 1.176.979.554 | 637.487.748 |
| Callback delle righe di cella | 455.301 | 70.007 |
| Operazioni DAG packed | 9.687.049.272 | 1.625.782.567 |
| Letture originali totali dei frame | 31.440.429 | 31.055.135 |
| Prodotti per fold dei valori | 595.120 | 45.512.396 |
| Massimo heap nominato | 722.744.244 B | 748.973.221 B |
| Massimo RSS/fisico stabile campionato | 826.650.624 B | 723.210.240 B |
| Campioni / incompleti / smaps fallite | 1.010 / 0 / 0 | 841 / 1 / 0 |

Rapporto prover 0,823134: **−17,69% osservato**, senza ripetizioni o
attribuzione separata alle due candidate. Non è una stima stabile del
guadagno e non si estrapola al modello intero. Heap nominato e RSS sono
conti diversi; i campioni non dimostrano il picco fisico istantaneo.
GPU a zero in tutti i campioni delle due prove e nel controllo finale.

Entrambi i verifier originali accettano punto/endpoint MAC, digest FS
e consumo di tutte le **9.919 correlazioni**. Wire 320.320 B ciascuna,
BLAKE3 uguale:
`8782b92eb0afecba42a6aeac830933daba5e401c94c06d7b59b96cbaabdad57c`.
Il confronto è fra digest delle wire complete; i byte delle due fixture
non sono esportati. Non è un certificato canonico o un'accettazione
durevole della sessione richiesta.

## Residuo e decisione

Le **30.985.128 letture dei frame nell'endpoint byte** sono identiche
nei due casi: totale meno i frame del replay packed. Il relativo tree
mantiene 41.844.736 getter e 167.378.944 valori scalari. Questo residuo
è distinto dai callback di cella e spiega perché una loro forte riduzione
non dimostra una riduzione comparabile di tutto il lavoro. Nessuna
attribuzione temporale separata è misurata per le fasi interne.

Nel dominio canonico lo screen pubblico conserva un upper del core di
481.289.178.399.996 prodotti Fp3, contro 751.359.028.655.932; esclude
endpoint byte e altro lavoro. La riduzione dei callback della fixture
non si trasferisce al dominio canonico, per cui il conto locale della
cache dà −28,11%. Costo RMS completo e conto simultaneo ammesso restano
aperti; le candidate rimangono disabilitate nel runner canonico.

Il seguito deve affrontare il lavoro residuo dell'endpoint originale,
insieme al core, mantenendo wire/FS/MAC e contabilità completa. Il solo
commitment A iniziale completato nella prima fase non basta per avviare
con credito il percorso completo. Non si rinnova un setup costoso sulla
base di questa sola fixture; nessun target 65 s attribuito.

Le identità distributive non scaricano sorting, indici, maschere, pesi,
fold MSB, determinismo della sorgente o lifetime Rust/Fp3. Nessun nuovo
lemma Lean di raffinamento; composizione malevola Seed6, ipotesi EA-LPN,
raffinamento CUDA/VMM e allowance fisica completa conservano i loro
obblighi documentati nel design e nella sicurezza attivi.

## Conservazione

- `artifact/c7.1-pod/certificates-rms-shared02-20261011/`: 61 file,
  38.269.297 B; manifest SHA-256
  `b6bb45fbebe4d1b67e6d28c69f34969412b204b12c403dc77e438a79aa8307d1`.
- `artifact/c7.1-pod/certificates-rms-shared02-close-20261011/`: 26 file,
  24.820 B; manifest SHA-256
  `2707e433e71edf0ad80a2e6d97799d65f066ebe6130508fec192f57aeb5699af`.

Hash verificati prima dello stop; ricevute provider/guard conservate
dopo la chiusura. Totale privato 545.111.778 B, entro 10.000.000.000 B.
Nessuna rimozione o modifica delle evidenze precedenti. I byte del
certificato canonico, la sua dimensione e il suo hash restano assenti.
