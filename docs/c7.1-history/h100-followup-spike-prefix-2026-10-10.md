# C7.1 — prefisso canonico e copertura del logger H100

Evidenza del seguito autorizzato sul pod `z6wx2kkn69eoc0`:
[record pubblico](../../benchmarks/results/c71-h100-followup-spike-prefix-2026-10-10-b9043c5d5f51.json).
Checkout iniziale pulito `b9043c5d`, runner compilato a `cfc04b6f`,
libreria diagnostica con pool/fill e filtro da 1 MiB a `b9043c5d`.
W packed e Γ ammesso sono riusati dopo verifica; la sessione AES è nuova.
Non sono riusate correlazioni né ripreso un journal terminale.

`canonical-spike01` completa W PCS (190,093 s), installazione
(212,493 s), setup AES (1.487,902 s), preparazione O=0 (76,013 s) e
35 dei 512 gruppi A. Gli ultimi gruppi completi richiedono circa 5,73 s
ciascuno, con 148.203 lanci e 31.740 allocazioni per gruppo. Sono campioni
diagnostici, senza confronto temporale controllato o credito canonico.
Il massimo temporaneo stabile campionato è 6.141.582.848 B, sotto il cap
6.174.015.488 B; anche i 16 MiB massimi di cache del trace lasciano
circa 15 MiB, senza dimostrare picco transitorio o allowance completa.

La traccia si arma al gruppo 30 e conserva 55.187 record,
16.776.993 B in 32,384 s: gruppi 30–34 completi, gruppo 35 parziale.
Il limite rifiuta il record successivo; l'owner termina, il cleanup
segnala fallimento e il monitor chiude per transizione W non risolta.
La traccia resta un prefisso negativo. Non dimostra il picco precedente,
la sua scomparsa o una causa interna al driver. Il successivo trial
`canonical-default02` usa la libreria default, senza logger/profiler,
con W/setup nuovi e timeout di 90 minuti entro la deadline di campagna.

La cattura ridotta `nsys-clock-probe02` allinea uno a uno 253 fence
owner con 253 API CUDA stream synchronize: intervallo degli offset
di ampiezza 1.292 ns. L'offset appartiene solo a quella cattura e non
viene trasferito al prefisso A. Nsight Systems 2025.1.1 avvisa che il
driver 13.0 è più recente; questo controllo finito non dimostra
compatibilità generale. La timeline esterna A con correlation ID resta
necessaria per completare l'attribuzione.

Artefatti privati verificati in
`artifact/c7.1-pod/h100-followup-spike-20261010T183000Z`: 47 file,
20.750.855 B, manifest SHA-256
`efe11553a57efbadee303344a23bd86ca69216de3f83a8cb3ab4361ff3c2449f`.
Il bundle precedente e i suoi manifest sono intatti. Zero certificati;
O=150/300 non iniziati; Γ ammesso invariato e nessuna nuova calibrazione.
