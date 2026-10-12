# Canonico interrotto: credito esaurito, prova finale non registrata

Il proprietario chiarisce nella conversazione: «si perche era esaurito il
credito.» La prima osservazione negativa del watcher è alle13:17:55 UTC;
seguono altre due connessioni rifiutate fino alle13:18:36. REST restituisce
404 `pod not found` e GraphQL `data.pod:null` alle13:36:52 e13:37:43 UTC.
Il meccanismo interno di rimozione non è osservato. Non classificare questo
esito come normale timeout, errore del verificatore o teardown GPU verificato.

Il [nuovo record immutabile](../../benchmarks/results/c71-certificates-canonical-unavailable-2026-10-12-16d60d38.json)
ha SHA256 `a04c0020f66cb28e73406db0c6b797106dd968b88e24039cf23ef7f94d46f267`.
Conserva collegamenti/hash dei quattro checkpoint precedenti, ricevute API,
errore SSH, sorgenti dei controlli e causa riportata dal proprietario.
Il nuovo bundle privato `artifact/c7.1-pod/certificates-canonical-unavailable-20261012`
contiene28 file/38.684 B riverificati; manifest precedenti invariati.

Sul codice pulito16d60d38 erano completati setup reale/AES, preparazione
inferenza O=0 e commitment A512/512; il corpo prova era avviato. **Zero
certificati completi registrati e zero accettazioni canoniche verificate.**
La risposta finale, il C71ACC01, i due journal durevoli e la summary
terminale non sono stati recuperati. L’exit code e lo stato finale della
generazione restano sconosciuti; i checkpoint non dimostrano una prova completa.
O=150/300 non hanno un risultato registrato. L’ultima osservazione del
processo in conversazione lo vedeva vivo alle12:42:45, senza response/ack.

Il provider non espone più quel pod; non è una ricevuta EXITED/runtime
assente. Guard94185 e watcher112243 risultano assenti al controllo locale,
senza un ritiro eseguito da questa chiusura. Nessun riavvio, pod sostitutivo
o nuova durata è autorizzato implicitamente da questi controlli. La finestra
originale conserva compute end13:19:04 e hard stop13:49:04 UTC.

La [candidata P0 per righe](p0-row-major-prepared-2026-10-12.md), commit
ead7bb432bdea39c6e36f4650d5724c2be3b1201, rimane preparata e non applicata
alla sessione16d60d38. L’ispezione trova lo stesso ordine dei termini per
colonna e una migliore località della cache a riga singola; compilazione,
parità getter/caller/wire e produzione non sono eseguite su questa candidata.
Nessun miglioramento temporale misurato è attribuito al run interrotto.

Il prossimo lavoro hardware è validare quella piccola correzione, poi dare
priorità a una sessione canonica completa O=0→150→300 con correlazioni
reali/AES nuove, KV vuoto e journal nuovi. Gli input Γ conservati sono
riutilizzabili; stato crittografico terminale e KV non lo sono. Servono
hardware disponibile e un nuovo ambito di spesa/durata autorizzato; la VM
rimane adatta solo al controllo leggero e alla preparazione del codice.
