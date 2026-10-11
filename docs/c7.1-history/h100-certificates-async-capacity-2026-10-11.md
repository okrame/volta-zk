# C7.1 — pool con free ordinato, 11 ottobre 2026

Il [record](../../benchmarks/results/c71-certificates-a-async02-2026-10-11-e1484890.json)
conserva il source pulito `e1484890`, la build e tre parità H100 passate:
trasformazione 0,803 s, root/aperture del sorgente 1,404 s e prova lineare
wire/FS/MAC 2,204 s. Non sono i 16 filtri richiesti per una nuova selezione.

Il componente A reale O=0 termina dopo 184,213 s al gruppo 0, senza
completarlo. Il controllo del pool osserva arena/used 5.257.283.328 B e
reserved 5.335.154.688 B: slack **77.871.360 B**, oltre i 64 MiB
addebitati. Il rifiuto è corretto. Il monitor termina negativo anche per
transizione W irrisolta; i campioni non coprono il picco istantaneo del
pool e non sono un’ammissione fisica. GPU idle confermata dopo teardown.
Il primo launcher aveva indicato un eseguibile inesistente: il failure
127 è conservato, la directory del retry è nuova.

La prova successiva aumenta soltanto la riserva **diagnostica** a 128 MiB,
addebitati interamente nel payload prima dell’uso. Il bound viene alzato
nel controllo del pool, senza cambiare i cap payload/arena/fisico della
campagna. Il componente A ha margine da verificare; il ledger generale
continua a bloccare la selezione canonica. I nove scenari simulati passano
con il nuovo addebito. Nessun RMS, PCS, MAC o parametro Γ viene modificato;
zero certificati generati e verificati.
