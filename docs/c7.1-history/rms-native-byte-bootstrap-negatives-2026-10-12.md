# RMS byte GPU — negativi di bootstrap e compilazione host

Tre trial nuovi sul pod autorizzato, checkout pulito `8a249df1`, preservano
esiti e provenienza prima delle correzioni. Cap fisico6.174.015.488B,
CPU AS64GiB e deadline della nuova finestra di sei ore invariati.
Tutte le esecuzioni avvengono sul pod; VM solo controllo/editing/hash.

- [byte01](../../benchmarks/results/c71-certificates-rms-native-byte-bootstrap-negative-2026-10-12-8a249df1.json):
  `/usr/bin/time` assente nel nuovo container. Il monitor si ferma prima
  del figlio test; summary vuoto e exit2 preservati. Nessun byte eseguito.
- [byte02](../../benchmarks/results/c71-certificates-rms-native-byte-pytest-negative-2026-10-12-8a249df1.json):
  monitor disponibile ma `pytest` assente, exit1. Nessuna compilazione
  del consumer. Installazione `python3-pytest` prima del nuovo trial.
- [byte03](../../benchmarks/results/c71-certificates-rms-native-byte-owner-compile-negative-2026-10-12-8a249df1.json):
  g++/UBSan/Werror respinge cinque `misleading-indentation`, tre nel
  consumer e due nel fixture host. Check14,608s, fisico campionato
  392.556.544B, GPU0, zero campioni incompleti; test runtime non avviato.

La correzione separa le istruzioni successive dai guard/loop, preservando
ordine e comportamento; non abbassa Werror. Nuova verifica owner e
CUDA/Rust/GPU ancora pendente. Kernel byte non compilati/eseguiti, nessun
credito matematico o canonico. Tutti gli archivi privati e manifest sono
nuovi e verificati; i tre negativi rimangono immutabili.
