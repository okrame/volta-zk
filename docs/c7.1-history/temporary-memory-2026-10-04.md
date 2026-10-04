# C7.1 — temporanei congiunti, 4 ottobre 2026

Questo checkpoint risponde all'istruzione di ridurre localmente la memoria
prima della campagna H100. L'autorità operativa resta nei cinque
[documenti correnti](../c7.1/design.md).

La versione precedente riservava 6.442.450.944 B CUDA anche durante il
coset CPU da 4.294.967.296 B: il subtotal 10.737.418.240 B violava già il
contratto. ABI 4 conserva un solo owner, ma addebita soltanto allocazioni
vive e le libera dopo fence. Il callback C/Rust e l'allocatore globale
contano congiuntamente entrambi i ruoli, anche capacità trattenute e
vecchio+nuovo di realloc; esentano soltanto il payload W packed immutabile.
Una free fallita conserva il debito, senza ritentare sul puntatore incerto.

Il riordino PCS usa quattro coset iniziali 2^20 per scan, due coset S1
2^23, coppie S2 2^21, tutte le query limitate a 2^20, fattori/resti/matrici contigui e
un solo sottoalbero rigenerato. S1 si ridimensiona dopo il rilascio del
predecessore. Il conteggio include i coset in attesa. Il numero di scan
iniziali resta W=1.024/A=512; le accumulazioni per coefficiente diventano
quattro (due per S1/S2). Questa scelta riduce il frontier pagando aritmetica
esplicita: non eredita i tempi o il credito di lavoro dei vecchi screen.
La finestra range A del runner scende a 1 GiB. Il numero di batch query
e di finestre range può aumentare: il costo resta nella prova. I vettori
dei claim rilasciano anche la capacità eccedente dei punti originali.
Le prove serializzate vengono rilasciate al loro ultimo consumer su
entrambi i ruoli. La soglia mmap glibc viene fissata a 128 KiB per evitare
il trattenimento adattivo dei grandi workspace host; restano due arene.

Il massimo **imposto** alle allocazioni è 5.905.580.032 B. Con una riserva
esplicita, ancora fisicamente non verificata, di 268.435.456 B per
runtime/allocator/stack, il ceiling analitico è 6.174.015.488 B e il margine
268.435.456 B. Non è un picco D34/D35 misurato. I subtotal per shape non
provano il completamento canonico; il controllo fisico dovrà completare
O=0/150/300 senza rifiuti di budget e con verifica/promozione corretta.
Il [ledger](../../scripts/c71_temporary_ledger.py) conserva questa distinzione.

I fallimenti intermedi restano evidenza: il primo test del nuovo release
ha esposto un double free della fixture che liberava il puntatore pur
restituendo errore; l'owner ora tratta quella proprietà come incerta.
Un'altra regressione aspettava l'errore al cleanup, ma il nuovo fence/free
lo rileva prima: è cambiato il predicato del test, non è stato ignorato
l'errore. Un filtro Seed6 con nome errato ha selezionato zero test e non
riceve credito. Il primo comando `nvcc` senza PATH ha fallito; la build
usa il toolkit locale preesistente 12.9.1 e non scarica dipendenze.

La build sm_90 dichiara 24 kernel, stack massimo 216 B/thread nel kernel
coefficienti e zero spill store/load. Questo è un risultato del compilatore,
non memoria fisica misurata o esecuzione CUDA. Nessun pesato reale,
allocazione canonica D34/D35, run GPU o costo RunPod è stato eseguito.
