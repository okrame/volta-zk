# RMS tail — stride/chunk ragged verificati

Fonte pulita `39aef3bcdedfbd24d68666278f03b38c6ac9b7b7`, sei check passati:
12 test calendario,9 documentali, build Rust471,107 s, regressione GPU
densa, nuova parità ragged e check produzione11,607 s. Il [record](../../benchmarks/results/c71-certificates-rms-tail-ragged-2026-10-11-39aef3bc.json)
ha SHA-256 `e4691bae9899ebe6819ef5f27971f7c242b6a4634747b6fb210aa21d35a5bb33`;
69 raw, archivio13.696.750 B, manifest/hash verificati in streaming.
Il [negativo precedente](h100-rms-tail-ragged-negative-2026-10-11.md) e
la sua correzione di provenienza restano immutati.

La nuova fixture aggiunge il Copy singleton richiesto dal validatore
originale. Gate per programma/profondità:129/513/1,257/1.025/1 e513/769/1.
Su125 celle vive/128 padded, tre casi con challenge generali/zero/uno e
punto cella Booleano:63 coefficienti e36 terminali coincidono con il
percorso denso CPU originale. Sono attraversati stride128 e chunk512,
con And/Xor/Copy, indici differenti, selector nulli e padding. Nessun
callback host frame; capacity coppie4, come nella geometria Runtime.

La regressione precedente16.384 celle/tre profondità conserva84
coefficienti e24 terminali,4.512 launch,61 allocazioni/rilasci e arena
4.005.632 B. La nuova fixture ha846 launch,91 allocazioni/rilasci,
arena5.307.392 B, owner42.496 B e arena finale0; nessun errore cleanup.
GPU idle ai bordi. Fisico ragged campionato496.975.872 B/GPU351.272.960 B,
zero incompleti. Denso e produzione hanno ciascuno un incompleto:
nessun credito al loro picco stabile o a un picco istantaneo completo.

Rust build: fisico campionato3.282.386.944 B, zero incompleti;
GPU556.793.856 B osservata e non attribuita, nessun isolamento dedotto.
Schedule/docs hanno GPU zero nei campioni. CPU AS64 GiB, CUDA senza
cap AS, arresti fisici/arena/deadline invariati. Il CUDA congelato c0e0448d
è riusato con hash verificato: cambiata solo la fixture/harness Rust,
nessun kernel o validatore indebolito.

Una [nuova conferma strutturata](../../benchmarks/results/c71-certificates-rms-tail-ragged-2026-10-11-39aef3bc/tail-schedule-confirmation.json)
collega la previsione280.299 dello screen b13ccaa2 al contatore GPU c0e0448d,
con hash dei due record originali e `original_records_unchanged:true`.
Il confronto del contatore denso4.512 e del159/99 passa nel calendario;
la previsione precedente rimane marcata non ancora confrontata al suo
momento storico. Nessun conto completo o tempo canonico ammesso.

La fixture ragged controlla gate pubblici, non un predicato RMS valido
o un certificato. Il [confronto AB/BA](h100-rms-native-paired-2026-10-11.md)
resta limitato al componente sintetico512/159/99. Byte GPU, statistica,
conto simultaneo/refinement, modello/real-AES, risposta e journal canonici
restano aperti. VM solo editing/controllo/verifica streaming. La durata
aggiuntiva è stata richiesta ma non autorizzata: scadenze originali invariati.
