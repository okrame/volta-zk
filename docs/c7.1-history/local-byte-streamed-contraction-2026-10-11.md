# Contrazione byte a memoria limitata — 11 ottobre 2026

Seguito locale del [benchmark RMS](h100-certificates-rms-shared-cache-2026-10-11.md).
Zero certificati canonici; provider fermo. La misura completa ridotta
conserva 30.985.128 letture nell'endpoint byte, identiche con e senza le
candidate per il core. La contrazione già esistente mantiene i polinomi
originali, ma tabella esponenziale dei prefissi e checkpoint fisso al
nono round ne impedivano il riuso diretto nel dominio canonico.

## Modifica e premesse

La rigenerazione usa `f(0) + sum_prefix Eq(prefix)*(f(byte)-f(0))`;
il supporto pubblico omesso è la baseline byte zero. Il percorso Eq
aggiorna soltanto il suffisso cambiato del contatore binario, senza
inversioni o ipotesi di sfide nonzero. Anche i pesi diagonali moltiplicati
per le feature seguono lo stesso fold. Restano gli otto livelli, le
sfide, il numero di correlazioni e l'autenticazione del driver originale.
I figli terminali sono recuperati dai byte originali dopo le sfide di
cella; non si ricostruiscono dalle sole direzioni quadratiche conservate.

Il checkpoint viene scelto dopo la trasformazione pubblica del livello,
secondo ranghi e supporto proiettato. Il costo comprende chiavi, Vec
esterni, Vec per riga e tutte le feature, con 8 MiB per stato. La capacità
reale viene ricontrollata; sorgente e destinazione coesistono fino al
completamento del fold. Se nessun checkpoint di cella entra nel budget,
la rigenerazione continua fino al recupero terminale. Non esiste una
allocazione proporzionale al numero di tutti i prefissi.

La candidata ammette al più 29 bit di cella, 16 lane e 16.384 intervalli
ordinati non vuoti e non sovrapposti. Il cap di 32 MiB è un upper
conservativo dell'evaluator: due stati entro 16 MiB; feature pubbliche,
vecchie/nuove durante la sostituzione, entro 8 MiB; trasformazione,
Eq fattorizzata, supporti, piccoli batch e figli originali entro altri
8 MiB. I ranghi massimi rimangono [4,8,16,17,9,5,3,2]. Le LUT ByteTrees,
proof, correlazioni e altri owner restano contati dal caller. Lo stack
locale dei pesi ha 30 Fp3; allocator e runtime non sono un picco provato.
Il vecchio wrapper ridotto mantiene il limite di 128 celle; il nuovo
wrapper verifica supporto/geometria prima di modificare FS o correlazioni.

RMS espone la candidata nel benchmark con
`C71_RMS_BENCH_BYTE_CONTRACTED=1`, indipendentemente da cache di cella e
gate condivisi. Il runner canonico mantiene il default zero. I contatori
separano letture originali, rigenerazione, checkpoint e stati; non
costituiscono ancora un conto completo delle operazioni aritmetiche.

L'identità usa distributività (`Finset.sum_mul`, `Finset.mul_sum`) e
somma unitaria dei pesi multilineari; il cammino incrementale usa i
fattori originali. Diagonalizzazione, associazione dei ranghi, supporto
modulo una potenza di due, indici MSB, recupero dei figli e lifetime
Rust/Fp3 restano premesse di raffinamento. Nessun nuovo lemma Lean.

## Controlli locali

La prima build raggiunge il timeout locale di 120 s. Il launcher aveva
applicato 64 codegen unit anche alle dipendenze, provocandone la
ricompilazione. Log e report restano conservati; il comando corretto
riusa il profilo già validato con 64 unit soltanto per volta-pcs.
Timeout 120 s e stop RSS aggregato 3 GiB invariati. Una seconda build
rifiuta la visibilità troppo stretta del nuovo tipo di contatori, poi
corretta; 14,581 s, exit 101. Le build successive passano in 58,069 e
60,373 s; quest'ultima include la prova a 256 celle, RSS aggregato
2.632.704.000 B. Nessun risultato hardware attribuito.

Passano quattro filtri Rust separati, AS 2 GiB/60 s/un worker:
coefficienti contro fold densi su supporti con buchi e sfide zero/uno,
prova byte completa a 256 celle, identità della contrazione su tutte
le 256 entrate dell'alfabeto e wire RMS mista. Il nuovo controllo della
prova rifiuta supporti sovrapposti, disordinati e fuori dominio prima
che FS o correlazioni cambino. Dopo la verifica positiva rifiuta un
leaf tag alterato. La pianificazione pubblica prova anche 29 bit senza
leggere byte o allocare il dominio.

La prova byte a 256 celle usa tutti gli otto livelli e 425 correlazioni:
wire 12.684 B identica al riferimento denso, BLAKE3
`8e2e23677c2184276225be7e3f32dacf67a199d49c06552992978269320cfc7e`.
Punto, endpoint MAC e digest FS coincidono; il verifier originale accetta.
2.768 chiamate al getter byte e stato trattenuto massimo 146.728 B.
La fixture RMS mista conserva wire 14.320 B e 472 correlazioni, con
letture dei frame **243.340→1.100**. Queste includono 12 frame del replay
di cella e 1.088 nell'endpoint. Le 1.152 chiamate al getter byte includono
anche lane zero pubbliche del caller; non sono tutte letture del frame.

Il test preesistente
`c71_b12_byte_functions_close_original_byte_macs_in_one_ranged_pcs`
termina con timeout a 60,008 s, RSS 90.390.528 B. I prefissi positivi nel
log non danno credito al test composto completo. Il limite non è esteso;
la parità RMS indipendente viene eseguita separatamente e passa in
13,117 s, RSS 129.359.872 B. Nessuna PCS del modello o accettazione
canonica deriva dai test nuovi.

## Piano pubblico e residuo

Gli intervalli delle 159 ricette ammesse si uniscono nel supporto delle
347.937.024 celle vive del dominio 2^29. Con 12 lane e ranghi massimi,
i checkpoint upper per gli otto livelli sono [18,19,20,20,19,18,17,17].
Ogni stato al checkpoint stimato occupa al più 8.290.592 B, entro 8 MiB.
I ranghi effettivi dipendono dalle sfide pubbliche; un rango più piccolo
può anticipare il checkpoint. Sono upper del piano, non esecuzioni
canoniche o conteggi esatti per una futura sessione.

Ogni round rigenerato legge una volta ogni byte nel supporto per lane;
la cattura aggiunge una scansione e il recupero terminale un'altra.
L'upper totale è **684.740.063.232 chiamate al getter byte**. Il percorso
letterale corrente ha 87.686.052.315.136 getter dei quattro figli:
unità diverse, senza rapporto di velocità attribuito. Trasformazioni,
feature, Eq, fold, callback del caller, PCS, AES e modello restano fuori
da questo sottoconto. La candidata non riduce i 481.289.178.399.996
prodotti del core già stimati separatamente per i gate condivisi.

Servono misura rappresentativa e conto completo prima della selezione.
Il benchmark nuovo non è stato eseguito sulla H100. La campagna resta
conclusa con provider EXITED/runtime assente alle 14:27:28 UTC e zero
certificati canonici; questa modifica è lavoro locale autorizzato.


## Record pulito

Il [record `63719021`](../../benchmarks/results/c71-certificates-byte-streamed-local-2026-10-11-63719021.json)
ha SHA-256 `322ea3b885e4b288a87cb17e581ec5a3ad6d35bbddf07847cac81eb8b64c58ca`.
Quattro filtri Rust, 23 test Python e un piano pubblico passano sul
checkout pulito, sempre un worker/AS 2 GiB/60 s. Massimo RSS della
ripetizione Rust 129.359.872 B; Python 146.231.296 B. La parità RMS
completa ridotta passa in 13,148 s; questo è tempo del test locale,
non del modello o della candidata isolata sulla H100.

Il binario è compilato prima del commit con gli stessi tre file sorgente,
verificati tramite digest prima e dopo i controlli. SHA-256
`4c87074f1591bb810d8dee749220a20412916435c2dc49c03e265aa10eb96054`.
I 34 artefatti, 128.372 B, comprendono log, comandi, provenienza, piano,
quattro build e il timeout PCS. Gli intermedi delle build di sviluppo
non sono snapshot sorgente/binario separatamente congelati; la build
finale 04 è quella legata ai digest e alla ripetizione pulita.
