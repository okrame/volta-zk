# RMS ragged — geometria della fixture rifiutata

Fonte pulita `8d1471f1a8bb73fdce4f6c8edace0c1691cca4de`. Passano12 test
del calendario,9 documentali, build Rust469,994 s e regressione GPU densa.
La fixture ragged termina con exit101 prima del Runtime: il validatore
originale `widths` richiede un ultimo livello singleton. La nuova fixture
aveva due livelli larghi; nessun coefficiente GPU è stato confrontato
nel caso fallito. GPU zero nei campioni di quel processo e idle dopo.

Il [record negativo](../../benchmarks/results/c71-certificates-rms-tail-ragged-negative-2026-10-11-8d1471f1.json)
ha SHA-256 `a8a3bbc1c1e8ef5c34703d6396c6e50690b1705b5ed29eb1696411fcbefaa074`;
58 raw, archivio13.687.976 B, hash verificati. La sua SHA fonte dichiarata
è errata per una sostituzione nell'exporter VM, benché `source.json` raw
sia corretto e immutato. La [ricevuta correttiva collegata](../../benchmarks/results/c71-certificates-rms-tail-ragged-negative-provenance-correction-2026-10-11-8d1471f1.json)
ha SHA-256 `7a74323f94b1c46326095b85426a26b3b0f161db559e07c09ec4ba5e5495becf`;
identifica fonte e hash autorevoli, senza sovrascrivere il record negativo.

Il nuovo trial aggiunge un Copy singleton: tre profondità,63 coefficienti
e36 terminali attesi. I due livelli ragged restano129/513,257/1.025 e
513/769. Corretto anche il marker della capacità coppie: con128 celle e
cap256 il Runtime usa4, non16 come nell'oracolo16.384. Nessun validatore,
kernel, protocollo o limite viene indebolito.

La build registra fisico3.068.010.496 B, GPU zero e zero incompleti.
I controlli CPU schedule/docs registrano rispettivamente
GPU556.793.856/553.648.128 B non attribuite: nessun isolamento dedotto.
La conferma dei contatori280.299 è già scritta in un nuovo raw collegato,
senza modificare lo screen predittivo. Esito ragged positivo ancora aperto;
zero certificati canonici. VM solo editing/controllo/verifica streaming,
nuovo commit/trial entro la finestra originale sullo stesso pod.
