# RMS byte GPU — implementazione candidata, verifiche pendenti

Dopo la [chiusura verificata](h100-rms-moments-close-2026-10-11.md), sono
scritti kernel, consumer privato C++, callback Rust e controlli del byte.
**Codice non compilato né eseguito**: pod EXITED, ulteriore durata ancora
senza autorizzazione. VM solo editing/read-only review/Git; nessun test,
screen numerico o build locale. Nessun esito GPU o credito canonico nuovo.

Il [consumer](../../cuda/c71_rms_byte.inc) è legato al sorgente mapped,
usa token privato e sequenza completa delle8 layer/16 lane. Metadata e
staging restano posseduti fino al fence positivo; source-retire è bloccato
mentre il consumer è attivo. I rifiuti non pubblicano coefficienti o
terminali; cleanup incerto conserva host e addebiti. Quattro nuovi simboli
sono richiesti quando il byte GPU è selezionato, senza fallback CPU.

I [kernel](../../cuda/c71_rms_byte.cu) rigenerano le feature dai byte P/S/Y
originali e mantengono uno stato Fp3 limitato a8 MiB. Il valore pesato è
`d*f`, con `d` pubblico invariato nella layer, quindi si conserva solo
`f`: distributività e linearità del fold sono premesse implementative.
Il checkpoint è scelto dalla geometria pubblica e restituito al caller.
Eq è fattorizzata senza divisioni; include challenge zero/uno. Histograms
pesati limitati recuperano i byte originali, padding e lane zero inclusi.
I figli sono ricostruiti con il merge frazionario originale dai256
coefficienti pubblici, senza duplicare l'intera tabella511 dei nodi.
Associatività del merge, layout MSB e sorgente/lifetime CUDA vanno verificati.

Le [callback](../../rust/volta-pcs/src/c71_matrix/byte_function/contraction/native.rs)
usano il percorso fallibile del range: errore prima della prossima
autenticazione/challenge, nessun getter CPU nella modalità selezionata.
Bind, tutti i round, FS/MAC, correlazioni e terminali originali restano
nel prover/verificatore esistente. Nessun nuovo statement, lemma Lean,
endpoint PCS, setup o scorciatoia per token. Il runner canonico mantiene
il default precedente; il benchmark usa l'opt-in `C71_RMS_BENCH_NATIVE_BYTE=1`.
Il caller RMS/PCS ha un ingresso sperimentale solo `cfg(test)`.

Capacità proposte: shadow/LUT host e device, owner dinamico, Eq, partials,
stato, histograms e pubblicazione sono addebitati dal Runtime. Stato e
histogram sono disgiunti dopo fence/ritiro. Il nuovo puntatore nel context
aggiunge8 B al layout ordinario atteso:42.504 B, da confermare compilando;
aspettative dei test aggiornate, vecchi record42.496 B immutati. La riserva
CPU pubblica è32 MiB; i buffer GPU si aggiungono nel census comune, senza
credito dai soli upper locali. Vec/stack, allowance driver, mapping,
transienti e ledger simultaneo completo rimangono da scaricare.

Prima di qualsiasi selezione:

1. Compilare/eseguire29 rifiuti del [consumer host](../../tests/test_c71_rms_byte.py),
   owner/trace/pool/source/tail/index e controlli API mancanti/owner estraneo.
   I nuovi stub simulano solo proprietà e fault, mai matematica GPU.
2. NVCC include anche `cuda/c71_rms_byte.cu` insieme ai sorgenti del Runtime;
   controllare linking/simboli, compilazione Rust e produzione.
3. Eseguire `c71_byte_native_mapped_all_eight_layers_original_dense_coefficients_and_children`:
   tutte le layer contro figli densi originali, query/challenge zero/uno.
4. Eseguire `c71_byte_native_mapped_streaming_checkpoint_matches_original_cpu_contraction`:
   dominio16.384, tutte le layer, streaming/checkpoint/fold e terminali;
   checkpoint GPU positivo deve essere osservato, non presunto dal test CPU.
5. Eseguire `c71_byte_native_mapped_wire_original_verifier_and_tampered_leaf`:
   wire/FS/MAC densi originali e leaf alterata respinta, getter CPU vietato.
6. Eseguire `c71_b12_gemma_rms_common_gpu_byte_dispatch_joins_both_original_roots`
   con onesto e due alterazioni, poi159/99 con opt-in e hash/correlazioni
   dei quattro CPU congelati. Nuovo SHA pulito, nuovi file e monitor.

Nessuna extrapolazione del target65 s. Il vecchio screen `credit:false`
conta ancora209.567.637 launch e1.328.755.507.200 posizioni tail; la nuova
matematica byte non chiude quel costo, statistica, ledger o raffinamento.
O=0/certificato/journal incompleti; O=150/300 non iniziati. Prove nuove sul
pod richiedono durata autorizzata; tutti i negativi vanno conservati.
