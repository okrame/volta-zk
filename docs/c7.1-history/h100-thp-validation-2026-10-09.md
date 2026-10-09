# H100: pagine grandi validate e code CUDA — 9 ottobre 2026

Il [record](../../benchmarks/results/c71-h100-thp-validation-2026-10-09-920e684d1789.json)
conserva la build Rust `920e684` sulla H100: 609,307 s, massimo RSS
campionato 2.935.619.584 B. Sei regressioni del runner, 15/15 test sulla
libreria CUDA reale e il diagnostico nonlineare passano. I sorgenti CUDA
sono invariati: la libreria sm_90 `a32a6c3` viene riusata dopo controllo hash.

`inference-04` termina in 278,166 s, senza stop, errori smaps o swap.
Inferenza isolata 85,392672384 s, preparazione 85,446341191 s; tutti i
150 token, il digest W, i contatori cumulativi e il cleanup sono identici
alla baseline scalare. Rispetto a 90,593679528 s: −5,201 s / −5,741% su
singoli run, senza attribuzione causale isolata né credito al target 65 s.
Il massimo temporaneo campionato resta pressoché invariato: 1.266.966.016 B
contro 1.267.047.936 B. THP da sola non risolve lo stop fisico canonico.

Il caricamento W regredisce da 65,858 a 153,661 s; residenza nativa 22,538 s.
Il probe dopo il caricamento osserva 59.099.136 KiB di AnonHugePages,
98,571% dei byte W. Una lettura smaps richiede 0,025467 s contro 0,927701 s
del probe precedente. Durante la preparazione 427 campioni hanno durata
mediana 0,058659 s, massimo 0,096689 s, sotto il target operativo 0,2 s.
Due letture diagnostiche extra sono dichiarate, una durante il caricamento
e una dopo. Questi dati non dimostrano i picchi tra campioni.

La [documentazione CUDA 12.8](https://docs.nvidia.com/cuda/archive/12.8.1/cuda-c-programming-guide/index.html#cuda-environment-variables)
definisce il numero di connessioni compute/copy. Quattro contesti vuoti
separati, stack 256 B, uno stream e un memset/free da 4 KiB misurano:
con entrambe le connessioni a 1, −1.048.576 B GPU e −49.205.248 B host,
complessivamente −50.253.824 B. Il probe usa un contesto senza C7.1 o W,
con la sola build CPU concorrente: nessun credito al picco del modello.
La riduzione della coda a un quarto dà un piccolo risparmio aggiuntivo,
ma non viene selezionata.

Anche `CUDA_DEVICE_MAX_CONNECTIONS=1` e
`CUDA_DEVICE_MAX_COPY_CONNECTIONS=1`, senza `CUDA_SCALE_LAUNCH_QUEUES`,
passano 15/15 CUDA reali e il diagnostico nonlineare. Il binario Rust e la
libreria restano identici, monitor `2ff8106`, checkout pulita `749b598`.
Il diagnostico completo `inference-05` deve ancora quantificare risparmio
e tempo: un nuovo trial canonico richiede quel risultato, riparte da W
e usa nuovi journal/correlazioni, entro cap e deadline originali.
