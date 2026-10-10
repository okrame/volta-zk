# C7.1 — finestra CUDA esterna e controlli del confronto

Il default `canonical-default02` termina per cap fisico dopo 116 gruppi A
completi, al gruppo attivo 116: 6.545.690.112 B contro 6.174.015.488 B.
Il picco storico non è risolto. Il prossimo diagnostico usa la build
large-only con arming 114 e cattura Nsight dopo 113 gruppi completi,
fino a 117 o al primo stop di risorsa. Sessione, journal e correlazioni
sono nuovi. Il costo del profiler può fermarlo prima della finestra:
anche quel prefisso negativo sarà conservato, senza aumentare limiti.

[c71_profile_window.py](../../scripts/c71_profile_window.py) tiene launcher,
comandi start/stop e applicazione nell'albero posseduto dal monitor
corretto. Solo milestone `end` di `pcs_a_resident` con geometria 512
attivano la cattura; progressi parziali e PCS W non la attivano.
Il termine della finestra richiede stop del collector e interruzione
diagnostica del native, con PID/start-ticks e pidfd: nessuna accettazione
o prosecuzione del journal. Il monitor esterno resta responsabile di
limiti/deadline e stop dell'intero albero. File/report e clock/correlation
ID vanno validati dopo la chiusura; una richiesta start/stop non dimostra
copertura. Due test locali verificano trigger e geometria originali.

Per il confronto SDPA già fissato, il controllo di finitezza del raw
`lm_head` precede il softcap, che potrebbe mascherare un infinito.
Tutti i 357 forward (warmup e due passaggi nei tre contesti) devono
attraversare il controllo; il report registra count e dtype. Controlli
e sincronizzazioni restano inclusi nei tempi forward. I due test del
workload passano; caricamento e hook reali attendono il trial CUDA.
