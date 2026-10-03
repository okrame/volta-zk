# Range W signed sul packed originale — 2026-10-03

Il [record locale](../../benchmarks/results/c71-signed-range-local-2026-10-03-ad9f5529d1ef.json)
conserva dieci test Rust, nove Python e due rifiuti CLI sulla revisione
`ad9f5529d1ef`, con `credit:false` e nessun certificato canonico.
Segue il [consumer range A](canonical-windowed-range.md).

Il medesimo evaluator ora opera anche su i16 signed. Il reader W enumera
solo le celle nell'intersezione della finestra permutata con ogni tessera,
leggendole dal packed originale condiviso; il suffisso esterno è zero.
Non copia W virtuale e non ricrea un protocollo range separato.
L'istogramma privato è calcolato una volta all'installazione; ogni prova
ne autentica i contatori con correlazioni fresche prima di alpha/rho.
Il timer `installation_w_commitment` include questo scan nel runner.

Si conserva la scelta [cut=11/m24](preflight.md), con 29 passate D35,
non il precedente cut=10/m25 incompatibile con gli altri residenti.
Lo staging è limitato a 2^27 parole, 256 MiB: limite implementativo,
non dimostrazione del picco simultaneo. Il conteggio richiesto comprende
anche il padding virtuale; non va confuso con i byte letti dal packed.
Il campo storico `byte_windows` conta finestre anche per W signed.

Il confronto completo W eseguito è D12, 3.001 parole vive e buffer
di 4.096 parole: 29 passate, 17 finestre Gram e 11 retention.
Wire, FS, forme e target coincidono con il prover denso; l'apertura usa
il commitment originale e un target MAC alterato è rifiutato.
Il gather controlla tessere ragged, estremi ±32.767, padding e rifiuti;
le intersezioni sono confrontate con enumerazione D1–D7.
La prova integrata O=0 ridotta usa ora il nuovo range W, ma mantiene
MAC ideali e il proprio percorso precedente per A. Non è Gemma canonico.
Per D35 sono controllati solo schedule e descrittori, senza payload.

Il primo test signed fallì perché la fixture riservava ancora le 32 righe
PCS di D10; D12 richiede `3*12+2=38`. La correzione cambia solo il test:
il fallimento e la ricompilazione sono conservati nel record. Il runner
era stato compilato prima di questa sola correzione `cfg(test)`; la sua
provenienza è distinta dalla build lib-test sulla SHA pulita.

Restano CUDA esatto end-to-end, consumer densi residui, conto fisico
simultaneo, Γ reale, tre certificati canonici e obblighi Seed6 aperti.
Il superamento analitico dei 40 MB nelle continuazioni e l'hard stop
provider non cambiano. Nessuna GPU, peso reale, pod o spesa è stato usato.
