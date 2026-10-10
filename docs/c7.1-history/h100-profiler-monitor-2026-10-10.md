# C7.1 — monitor dei processi avviati dal profiler

Il probe hardware `nsys-session-identity01` passa e mostra che
`nsys launch` rende l'applicazione leader di una nuova sessione Linux.
Il monitor precedente conta i figli tramite PPID, ma richiede la sessione
originaria per esentare W e arresta solo i gruppi di quella sessione.
Usarlo invariato per una cattura canonica avrebbe rifiutato il census
e lasciato l'applicazione fuori dal suo arresto.

La correzione conserva la verifica PID/start-ticks e accetta W in una
nuova sessione solo quando la catena dei parent raggiunge il processo
avviato dal monitor. Le identità dei figli osservati restano registrate:
RSS/swap dei figli ancora vivi e dei loro discendenti sono contati anche
se successivamente orfani. Una PID riusata non eredita proprietà o esenzioni.
L'arresto conserva i gruppi della sessione originaria e usa pidfd per
segnalare le identità possedute nelle altre sessioni. I limiti, le verifiche
smaps, il census CUDA, le transizioni W e il guard provider sono invariati.

Passano 41 test del monitor e nove controlli documentali in 4,50 s sotto
60 s/2 GiB AS locali. I nuovi casi includono W realmente mmap in un figlio
di nuova sessione, arresto per deadline di un figlio in nuova sessione,
RSS di un orfano, rifiuto di W estraneo o con start-ticks cambiato e nessun
segnale a una PID riusata. Il device nei test del monitor è simulato.
Il primo assemblaggio della nuova fixture aveva spostato il controllo
PermissionError nel test errato: fallimento conservato nella cronologia
dei tool, corretto prima del commit. Non era un risultato hardware.

Il tentativo `canonical-default02` già avviato continua con il modulo
monitor precedente caricato in memoria. Non viene attribuita a questa
correzione la sua contabilità o il suo esito. La nuova gestione va
verificata nella cattura hardware successiva prima di farvi affidamento.
Non è introdotto un lemma di raffinamento né credito di picco completo.
