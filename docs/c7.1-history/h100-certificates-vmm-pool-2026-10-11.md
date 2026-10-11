# C7.1 — VMM e pool nella fase A, 11 ottobre 2026

Il trial VMM senza pool `a-vmm01` richiede 61–65 s per gruppo osservato,
contro circa 6 s nel precedente pool A. La differenza non attribuisce una
causa: il processo è stato osservato in `vm_mmap_pgoff`, ma mancano prove
di causalità. Il trial viene interrotto con SIGTERM verificando PID e
start ticks; nessuno stop fisico, GPU idle al termine. Il [record](../../benchmarks/results/c71-certificates-a-vmm01-2026-10-11-abf57c4a.json)
conserva 14/512 gruppi, 1.770,680 s totali, massimo fisico campionato
5.700.111.872 B, nessuna failure di risorsa o lettura smaps. Bundle privato
`certificates-a-vmm01-20261011T112800Z`, 17 file, manifest SHA-256
`d00759d78890b7d3364aa0ade91ef5d34e936bebee44cc6d5ba8f7c1ee89d915`.

La nuova ipotesi combina i componenti già verificati: VMM conserva gli
indirizzi e rinvia il backing di code pubbliche A/KV; il pool CUDA resta
attivo soltanto durante A, con riserva contabilizzata di 128 MiB. I buffer
VMM non appartengono al pool. Il rimborso del pool richiede fence, assenza
di buffer pooled e reserved/used zero; il KV VMM può restare vivo.

Passano 45 scenari host (22 VMM, 23 combinati), inclusi fault e confronto
di valori A dopo padding/FFT. Owner combinato 50.880 B. Il test del ledger
rifiuta la combinazione senza ricevuta esplicita di parità del lifetime;
le sei fasi iniziali rientrano nel payload, senza credito fisico.
Controlli preliminari: 13 test, 28,86 s, AS 2 GiB, un worker.

Sono necessarie parità H100 prima del nuovo trial O=0. Nessuna nuova
premessa algebrica: proprietà driver, fence, ownership e contabilità
restano premesse implementative non raffinate da un nuovo lemma Lean.
RMS completo e il superamento nominato O=300 restano aperti. Nessuna
root A del modello o certificato canonico deriva da questi controlli.
