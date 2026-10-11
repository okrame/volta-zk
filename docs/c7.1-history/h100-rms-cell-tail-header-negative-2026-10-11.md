# RMS cell-tail — negativo del primo header

Checkout pulito `291e2f4056119da721798a33d51f890076067116`, pod H100 originale,
finestra invariata. Il [record immutabile](../../benchmarks/results/c71-certificates-rms-cell-tail-negative-2026-10-11-291e2f40.json)
conserva19 file/52.488 B e campioni: tre test owner falliscono in compilazione,
un test algebra passa. Il nuovo header usa `c71_range::Fp3`, ma Fp3 è globale,
e dichiara tipi CUDA prima dell'include. La correzione rimuove il using errato
e include `cuda_runtime_api.h`. Nessuna build Rust o prova GPU di questa
candidata è stata eseguita; zero certificati, nessun credito matematico.

Il record ha SHA-256 `1a9d7fad08bc6f2324c784c5a6f3d08041b00461a5deb862443fa4c0992ceb15`.
Il nuovo trial usa checkout pulito e directory distinta; nessun file del
negativo è modificato. La VM ha fatto solo editing, controllo e conservazione.
