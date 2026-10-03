# Riduzioni S1 dalla sorgente originale — 3 ottobre 2026

Checkpoint successivo alle [query a finestre](canonical-query-windows.md).
Le istruzioni correnti restano nei [cinque documenti attivi](../c7.1/design.md).
Il [record pulito 989efa7](../../benchmarks/results/c71-residual-scan-local-2026-10-03-989efa70c151.json)
conserva 29 test Rust, 9 controlli documentali, due rifiuti CLI e build/lint
passati. Il primo tentativo di compilazione aveva un bound `Field` senza
import: corretto qualificandolo `p3_field::Field`, con errore conservato.
Una [correzione collegata dei metadati](../../benchmarks/results/c71-residual-scan-metadata-correction-2026-10-03-989efa70c151.json)
estrae le durate numeriche già presenti negli stdout: il parser del record
le aveva lasciate `null`. Non modifica il record originale né ripete i test.
`credit:false` e `readiness:false` rimangono espliciti.

La schedule selezionata nel [preflight](preflight.md) prevede 35 passaggi
S1 non-query: singleton, 32 coset, OOD e rigenerazione S1. Non è lecito
fonderli attraverso una root o una sfida FS. Prima di questo collegamento,
il residuale e i coset extension ricostruivano ogni cella folded tramite
getter scalari dell'originale. Per A ciò riattivava le finestre minime,
senza sfruttare l'ordine causale dei produttori già disponibile.

Ora `ReplayModel` passa lo scanner originale allo stato residuale. Ogni
byte all'indice `j*2^n+i` contribuisce a `i` con peso `Eq(prefix,j)`;
il callback riceve contributi, non valori folded distinti. La somma
commuta col singleton, con la riduzione del coset e con MLE/OOD.
Il prefisso è quello MSB già fissato. Gli zeri pubblici esterni non sono
emessi, i byte interni biased rimangono quelli del produttore originale.
Controlli di dominio, cardinalità ed errori non sostituiscono la premessa
di unicità/immutabilità dello scanner interno.

I coset extension scrivono direttamente i tre limb nativi in un buffer
column-major, mantenendo i pad alle posizioni originali. Ogni colonna
base riusa un buffer FFT e la stessa coppia di twiddle. La matrice completa
interleaved e la conversione row-major rimangono solo nel riferimento
di test. Non è un conto fisico completo: coset, colonna, twiddle,
pesi fattorizzati, Merkle, preparatore e altri owner coesistono.

S1 è materializzata soltanto dopo l'apertura del predecessore prevista
dal caller WHIR. Una scansione fallita non installa valori parziali;
la prima fold successiva richiede la retention. Dopo l'installazione,
il residuale elimina il proprio scanner e usa S1. Gli snapshot e i root
storici mantengono i loro owner: questo non dimostra liberazione di
checkpoint, RSS o HBM, né una fence GPU.

I controlli ridotti confrontano singleton, round sumcheck, MLE, OOD
(punti zero/uno/extension e pad nonzero), coset e S1 con riferimenti
densi indipendenti. Coprono prefissi vivi vuoti, parziali e completi,
emissioni non monotone, errori dopo contributi e propagazione immediata
degli errori del consumer. La catena D10 con MAC originali rende il
getter scalare originale un panic: root, codec, transcript, monete,
endpoint e verifica devono ancora coincidere con la prova densa. Il
conteggio delle scansioni deriva dalla geometria ridotta, non impone
32 coset al fixture e non attesta 35 passaggi canonici eseguiti.

Il cap D16 dello stato e il rifiuto degli oracoli extension grandi restano.
Mancano accelerazione Eq/Pow canonica, range a finestre, workspace query,
kernel densi, integrazione CUDA, contabilità simultanea e composizione
canonica positiva. Non sono blocchi risolvibili acquistando hardware.
Pesi/calibrazione e misure H100 richiedono autorizzazione e il blocco
provider sul controllo di spesa resta. Zero certificati canonici,
nessuna GPU/spesa, obblighi Seed6 aperti e continuazioni oltre 40 MB.
