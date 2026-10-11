# C7.1 — lifetime del pool iniziale A, 11 ottobre 2026

La riserva permanente di 128 MiB non entra nel ledger delle fasi E.
La nuova variante diagnostica la addebita prima del commitment iniziale A,
incluso il prescan dei salt, e la restituisce soltanto dopo fence, trim e
lettura positiva di reserved=used=0. Il runtime rifiuta annidamento,
transazioni attive e buffer del pool ancora vivi. I buffer legacy possono
restare vivi: vengono contabilizzati separatamente dal backing del pool.
W e le fasi esterne al commitment mantengono il loro allocatore.

Il caller delimita l’intero `Tree::commit_resident_source`, prima di
pubblicare la root. Ogni errore termina il proprietario e conserva il
debito incerto fino al cleanup; il logger fallito non impedisce un drain
sicuro, mentre un fence CUDA fallito impedisce di liberare i buffer pooled.
Non si cancellano fence o controlli numerici. Il flag numerico trattenuto
è creato dall’inferenza precedente, quindi è legacy; un caller che lo
creasse per la prima volta dentro il pool verrebbe respinto alla chiusura.
La fixture A usa la stessa premessa e la controlla con un’operazione
numerica prima del commitment.

Owner diagnostico 42.168 B, runtime Rust +16 B, record del pool 1.024 B,
stack diagnostico conservativo 10.240 B. Il file resta limitato a 16 MiB,
interamente aggiunti dal monitor al campione fisico. Cap invariati.
La variante resta vincolata alle macro diagnostiche; nessuna selezione
canonica o nuova premessa formale scaricata.

Verifiche locali preliminari, entro AS 2 GiB/60 s: 14 scenari del driver
simulato e otto test del ledger passati, 13,85 s complessivi; root, aperture
e istogrammi A esatti passati in 23,04 s; quattro simboli obbligatori
passati in 39,10 s; census pubblico aggiornato passato in 5,84 s.
La build Rust mirata passa in 58,89 s, massimo RSS aggregato 2.603.880.448 B
entro lo stop 3 GiB/120 s. Un primo wrapper del test non parte perché
`/usr/bin/time` locale è assente; il retry usa il modulo `resource`.
Il primo scenario simulato aveva creato il flag dentro il pool e ha
correttamente rifiutato l’end; la fixture corretta anticipa il flag.
Questi controlli precedono il commit; il run di record userà la SHA pulita.

Il ledger aggiornato ha ancora 653 fasi, senza credito fisico o ammissione.
Le somme nominate di accumulo A includono owner, metadati Rust e riserva:

| Contesto | Byte nominati | Margine sul payload |
| --- | ---: | ---: |
| O=0 | 5.890.193.534 | 15.386.498 |
| O=150 | 5.929.515.102 | −23.935.070 |
| O=300 | 5.968.836.670 | −63.256.638 |

La riserva non viene trasferita alle fasi di prova. Soltanto O=0 supera
questo controllo analitico nominato; gli altri due contesti richiedono
ancora una riduzione esatta. Il record non concede credito congiunto.
Il trial H100 `a-async04` già avviato rimane sulla precedente SHA pulita
`a525ecf8`, con pool permanente; nessun cambio del source durante il run.
La variante con lifetime limitato deve ancora essere misurata su H100.
RMS/GKR completo resta aperto, zero certificati canonici.
