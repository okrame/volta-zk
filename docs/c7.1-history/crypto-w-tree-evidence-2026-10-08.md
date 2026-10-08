# C7.1 — evidenza pulita Tree W, 8 ottobre 2026

Sorgente `6b3535856cc524d288bf0f3c98edd5a12aa6832f`, tree pulito,
[record](../../benchmarks/results/c71-crypto-w-tree-local-2026-10-08-6b3535856cc5.json).
Segue la [decisione Tree](crypto-w-tree-2026-10-08.md), senza modificare
quella decisione o i record precedenti. Il goal completo rimane attivo;
nessuna campagna H100 autorizzata.

Nove selezioni Rust eseguono 12 test positivi; nove controlli Python
documentali passano. Sempre un processo/worker, test 60 s / 2 GiB AS.
Build offline/locked mirata con un job, crate O0 e dipendenze O2:
56,42 s, compiler RSS 2.464.067.584 B distinto dai test. Massimo RSS
test/compilatori discendenti 206.602.240 B. I tempi della VM differiscono
dallo sviluppo; il microbench usa metodi nel medesimo binario.

Root, pad, sali, lavoro e aperture con getter effettivo coincidono con il
riferimento. La costruzione non chiama il getter. Capacità native massime
2.699.776 B, owner host 37.064 B, arena viva finale zero e D2H 4.328 B
di flag/digest; il counter congiunto include host, FFT/pad e owner.
Il confronto composto D15 verifica bytes di prova/codec (2.735.188 B),
transcript, RNG, target e chiusura dei MAC originali. La tabella iniziale
di riferimento da 16 MiB è soltanto nella fixture e conteggiata: non è
una cache di produzione o un benchmark del replay CPU delle aperture.
I MAC del test composto sono ideal; il runner conserva AES reale.

1792 casi di divisione monica verificano tutte le basi Fp3, punti zero,
duplicati e segni. I metodi diretti per grado ≤8 evitano piccole FFT;
regressioni indipendenti verificano righe/pad/suffisso pubblico e letture
originali. La catena delle finestre byte A con MAC/transcript originali
passa. Il conto A non cambia: 512 ricostruzioni iniziali per risposta.

94 artefatti sono conservati con digest. Otto esiti negativi includono
cinque timeout della catena D15 non cached, due build O1 fallite/deadline
e EPERM della socket locale. Il replay non cached resta un obbligo aperto,
preservato ignored e senza credito; i prefissi mostrano l'hotspot query.
La socket Unix passa con eccezione circoscritta; non usa rete esterna.
Sul timeout O1 il `wait4` non conta il compiler non raccolto da Cargo;
quel piccolo RSS non prova un limite del compiler.

La nuova evidenza corregge il subtotal device W con +256 B per il secondo
flag simultaneo: 3.736.793.344 B. I precedenti record restano immutabili.
Envelope nominato con host e upper device replay 4.611.875.272 B, prima
degli altri owner host addebitati dal budget. Non è un picco canonico.
W CUDA seleziona 128 scansioni, ancora analitiche per il pinned; nessuna
esecuzione CUDA, parità hardware o accelerazione H100 è stata misurata.
Restano A residente, confronto limb Tensor Core, sampler, aperture e altre
fasi crittografiche; la nuova campagna richiede autorizzazione hardware/durata.
