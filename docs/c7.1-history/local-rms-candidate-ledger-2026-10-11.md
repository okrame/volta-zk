# Conto simultaneo delle candidate RMS — 11 ottobre 2026

Seguito locale della [contrazione byte](local-byte-streamed-contraction-2026-10-11.md).
Zero certificati canonici. Pod fermo dalle 14:27:28 UTC; termine calcolo
originale 15:01:18 e hard stop 15:31:18 UTC. Nessun nuovo trial o setup AES.

## Modifica e capacità

Il [ledger](../../scripts/c71_temporary_ledger.py) espone lo switch
`--rms-candidates` soltanto con backend `s1-prepared`. Aggiunge due fasi
per contesto al conto esistente; non seleziona le candidate nel runner.
Il vecchio inviluppo RMS resta interamente addebitato in entrambe:
checkpoint CompactFrames, circuiti, replay, indici, claim W/A/KV,
Writer, PCG, metadati e arrotondamento VMM. Anche quando replay e indici
sono già ritirati nel codice, il loro upper è mantenuto conservativamente.

La fase di cella aggiunge cache folded 16 MiB e piano/builder condiviso
32 MiB. Il builder precede la cache, ma qui anche i due massimi sono
sommati. Entrambi muoiono alla fine della fase di cella della profondità,
prima della riduzione sugli indici e dell'endpoint byte.

La fase byte aggiunge separatamente:

- LUT originali: `16*256*511*48 = 100.466.688 B`;
- coefficienti: `16*256*24 = 98.304 B`;
- evaluator della contrazione: 32 MiB, inclusi due stati da 8 MiB;
- copia del supporto compilato: al più `16.384*8 = 131.072 B`;
- proof e triple del driver byte: 43.584 B;
- punti del driver e Eq della foglia, incluse sostituzioni: 12.552 B.

La somma dei nuovi termini byte è 134.306.632 B, distinta dai 48 MiB
aggiunti alla fase di cella. Il pool 128 MiB rimane confinato al
commitment iniziale A e non compare nelle fasi RMS.

La revisione ha inoltre individuato che il vecchio inviluppo RMS non
esplicitava le proof GKR trattenute e le triple dei prodotti. Il conto
corrente aggiunge 1.918.464 B anche senza lo switch candidato:
`(128+64)*120 + 128*((64+32)*24 + 64*8*24) + (128+64)*3*48`.
Il bound usa fino a 128 livelli, 57 round per livello (29 bit di cella e
due indici da 14 bit), capacità 64 per il Vec dei round, capacità 8 Fp3
per il wire di un round e sovrapposizione vecchio/nuovo dei Vec.
I record SourceCellWork sono già addebitati separatamente. Le LUT e
le proof byte sono aggiunte nella sola nuova fase esplicita; il vecchio
inviluppo non viene promosso a un conto completo dell'endpoint baseline.

Sono premesse da sorgente: geometry pinned, layout a 64 bit, capacità e
crescita Vec della toolchain, lifetime dei blocchi Rust e upper interno
della contrazione. Nessun nuovo lemma Lean raffina queste proprietà.
Resta separata la verifica fisica di allocator, runtime e driver.

## Risultati dello screen

Input copiati senza modifiche dal [record VMM + pool](../../benchmarks/results/c71-certificates-vmm-pool-local-2026-10-11-6ccb54a1.json),
con owner 50.880 B, granularità 2 MiB, export e flag trattenuto inclusi.
Tutti i nuovi termini passano anche attraverso la trasformazione VMM
comune; nessun contatore del componente sostituisce la somma degli owner.

| Contesto O | RMS cella candidato | RMS byte candidato | Massimo generale | Margine payload generale |
|---|---:|---:|---:|---:|
| 0 | 4.632.881.175 B | 4.716.856.159 B | 5.822.936.466 B | 82.643.566 B |
| 150 | 4.849.776.967 B | 4.933.751.951 B | 5.863.932.418 B | 41.647.614 B |
| 300 | 4.944.243.959 B | 5.028.218.943 B | 5.934.646.130 B | −29.066.098 B |

I massimi generali restano in `native_E_D34_A*_S2_predecessor_E_query_publication`.
Il payload comune è 5.905.580.032 B. Il limite O=300 precedentemente
noto rimane negativo e non è nascosto dal nuovo massimo RMS.
I margini O=0/150 sono analitici: niente fit fisico, prestazione H100,
PCS reale, accettazione o certificato. `joint_admitted:false`.

I test locali confrontano le fasi con e senza candidate, la separazione
dei lifetime e la conservazione degli owner, rifiutano i backend
incompleti e mantengono visibile il superamento O=300. Il codice di
protocollo non cambia e non richiede una nuova compilazione Rust/CUDA.

Il [record pulito `bef98394`](../../benchmarks/results/c71-certificates-rms-candidate-ledger-local-2026-10-11-bef98394.json)
conserva 31 artefatti, 1.566.218 B, tutti verificati per dimensione e SHA256.
I 18 input copiati coincidono col manifest VMM + pool originale.
Passano 15 test del ledger (0,412 s, RSS 32.149.504 B) e 9 documentali
(1,114 s, RSS 59.617.280 B). Lo screen delle 659 fasi richiede 0,025 s,
RSS 25.137.152 B. Ogni invocazione usa AS 2 GiB, 60 s e un worker.
I log di sviluppo precedenti sono separati; nessun failure nuovo.
SHA256 del record:
`29a96fee45da532862c623b14760e638ab956ecc3fa29a1869e4606f54d79013`.
