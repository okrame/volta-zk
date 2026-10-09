# H100: costo procfs e candidata per le pagine W — 9 ottobre 2026

Il [record](../../benchmarks/results/c71-h100-thp-candidate-2026-10-09-920e684d1789.json)
conserva un probe di sola lettura durante il setup di `canonical-04`.
Una lettura di `/proc/PID/smaps` richiede 0,928 s. La mappatura di W
usa pagine da 4 KiB, `AnonHugePages=0` e `THPeligible=0`; il provider
ha THP e defrag in modalità `madvise`. I campioni ordinari durano spesso
circa 0,65 s, oltre il target del monitor di 0,2 s. Le attese osservate
in `vm_mmap_pgoff` e `__vm_munmap` motivano l'ipotesi di contesa sulle
mappature; non sono una dimostrazione causale isolata.

Il primo probe legge smaps ma fallisce nell'estrazione per il nome errato
`capacity_bytes` invece di `bytes`; la ricevuta di errore è conservata.
Il probe corretto non cambia memoria, impostazioni del kernel o input.
Le due letture extra avvengono durante il setup e sono dichiarate come
possibile interferenza diagnostica. Il checkpoint W già completato è
separato: PCS 405,194766209 s, installazione 441,657392425 s.

`920e684` consiglia `MADV_HUGEPAGE` sulle sole pagine intere interne
all'allocazione posseduta di W, prima del primo accesso. Non aumenta la
capacità, non crea copie o cache e non modifica le impostazioni globali.
Un errore dell'API ferma il caricamento. Il consiglio non garantisce che
il kernel usi pagine grandi: occorre osservarlo sul nuovo processo.
Il monitor continua a usare la residenza effettiva e i limiti originali.
Byte, digest, Γ, semantica e garanzie del protocollo sono invariati.

La prima build locale raggiunge 120 s ed esce 124, senza superamento del
limite di memoria. Il nuovo tentativo, con dipendenze già compilate e lo
stesso limite, termina in 55,833 s, picco aggregato campionato 2.719.260.672 B.
Il test del reader passa per input piccoli, lunghezza errata, marker MIN
e 2 MiB di dati: valori e BLAKE3 esatti. Passa anche la ripetizione sulla
checkout pulita dopo il commit. Le build precedono il commit e il record
ne dichiara lo stato dirty e l'identità dei byte poi commessi.

Non c'è ancora validazione H100 o guadagno attribuibile alla candidata.
`canonical-04` resta su `a32a6c3`, senza questa modifica. Dopo il suo esito
terminale, entro la deadline, occorrono build compatibile, test pertinenti,
parità reale e diagnostico numerico con misura della residenza; nessuna
sessione o correlazione del trial attivo verrà riusata.
