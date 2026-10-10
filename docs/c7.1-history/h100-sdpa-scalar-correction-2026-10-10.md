# C7.1 — correzione dei 60 scalari pubblici nel confronto SDPA

`optimized-bf16-source-01`, checkout pulito `b2468f3e`, termina exit 1
durante il caricamento in 171,669 s, senza stop di risorsa. Il diagnostico
assumeva erroneamente che i 60 scalari pubblici di layer fossero unitari.
Non produce tempi forward o confronto completo; raw stderr e negativo
sono conservati, nessun risultato viene sovrascritto.

Il [manifest immutabile](../../manifests/c7-d126-gemma31b-source-metadata-v1.json)
contiene forma, offset, byte BF16 e valore dyadico di ciascuno scalare;
per esempio i bit del layer 0 sono 15814, già differenti da 1 BF16.
Una lettura di soli due byte ai 60 offset sui corpi shard verificati
conferma tutti i valori bit per bit. `optimized-layer-scalar-check02.json`
registra PASS con CPU AS 64 GiB. Il primo probe Torch/mmap fallisce nel
medesimo limite AS; la lettura agli offset evita mappature complete.

[Loader](../../scripts/c71_optimized_inference.py) corretto: verifica layer,
nome, dtype, forma e bit BF16 contro il manifest prima della copia CUDA.
Non modifica W/Γ o il runner intero, che già usa questi scalari pubblici.
Il termine «unitari» nel [metodo precedente](h100-comparison-plan-2026-10-10.md)
è una decisione superseduta da questa correzione; non si corregge il
documento congelato. Restano backend SDPA, le due precisioni, final KV,
hook raw-head prima del softcap, monitor e deadline.

Nuovi output `optimized-bf16-source-02` e `optimized-i16-dequant-bf16-02`
con codice corretto e checkout pulito. La parità dei 60 scalari è un
controllo di input del diagnostico, non credito di inferenza o di prova.
