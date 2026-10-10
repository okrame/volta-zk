# C7.1 — adozione degli agenti Nsight orfani

Il controllo `nsys-owned-stop02` ferma l'applicazione ma lascia l'agente
`--start-agent` a PID 1. Il suo PASS riguarda solo l'applicazione,
non l'intero profiler. La ricevuta è conservata e corretta da un nuovo
`nsys-owned-stop02-correction.json`: nessuna sovrascrittura. Gli agenti
dei due tentativi interessati sono ritirati tramite pidfd, dopo verifica
di eseguibile, sessione e identità. Il trial `canonical-profile03` è
interrotto nel caricamento prima di usare quella contabilità incompleta.

Il monitor ora attiva e ripristina `PR_SET_CHILD_SUBREAPER`: Linux gli
riassegna gli orfani discendenti, che restano nell'albero contato e
arrestato. È la semantica del [manuale Linux](https://www.man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html).
La discendenza dal monitor subreaper è ammessa insieme alla discendenza
dal launcher originario; PID/start-ticks e smaps restano obbligatori.
Lo stop ripete il census prima dei pidfd e raccoglie i figli adottati
terminati; lo stato subreaper precedente viene ripristinato. Limiti,
deadline e guard provider non cambiano.

Passano 43 test del monitor in 4,85 s sotto 60 s/2 GiB AS. I nuovi casi
verificano un processo in nuova sessione anche quando il parent termina
prima di lui. Il successivo probe hardware deve controllare sia target
sia agente, prima del nuovo trial canonico con file/correlazioni freschi.
Nessun credito di picco completo, attribuzione dello spike o protocollo.
