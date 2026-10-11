# C7.1 — rilascio del pool CUDA, 11 ottobre 2026

Il [record immutabile](../../benchmarks/results/c71-certificates-async-preflight-2026-10-11-221fb2bb.json)
conserva tre build pulite e i preflight negativi, inclusi due errori del
launcher e la correzione del record di rifiuto. Nessun trial A del pool
è ancora partito e nessun certificato è stato generato o verificato.

Sul source pulito `221fb2bb`, il filtro di trasformazione termina a
0,604 s dopo il rilascio dei primi quattro buffer: arena 0 B, pool
reserved 0 B e used 1.024 B. Il primo blocco fisico riservato era
32 MiB. Questi contatori non dimostrano superamento dei 64 MiB; il
controllo conservativo rifiuta la coppia incoerente. La GPU torna idle.
Non si indebolisce il controllo per far passare il test.

La revisione successiva usa `cudaFreeAsync` sullo stream dell’owner,
poi sincronizza, incrementa il contatore delle fence e richiede trim.
I fence precedenti restano. La [documentazione NVIDIA](https://docs.nvidia.com/cuda/cuda-runtime-api/cuda_runtime_api/group__CUDART__MEMORY__POOLS.html)
distingue il free accodato dal suo completamento osservato dall’host;
il trim può trattenere allocazioni senza tale completamento. W mantiene
il proprio free legacy. I nove scenari simulati verificano anche errori
del free accodato e della fence successiva, senza doppio rilascio o
restituzione di debito incerto. La parità hardware della revisione resta
da eseguire. Riserva payload 64 MiB, owner 42.160 B, cache file 16 MiB
e cap fisici sono invariati; la selezione canonica resta bloccata dal
margine del ledger generale. RMS/GKR completo rimane un ostacolo distinto.
