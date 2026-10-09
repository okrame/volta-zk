# Closure lineare sul common owner — 9 ottobre 2026

Source `31280382f6814a929f7651cd2c31fdd73e668952`, baseline `9033c64`.
Il [record pulito](../../benchmarks/results/c71-crypto-linear-local-2026-10-09-31280382f681.json)
ha SHA256 `2e198bc471aeb8bb813027af53ea19ecef9f4e96a4e00a003ad819c93d330f81`:
11 invocazioni, una build calda, 10 test Rust e 20 Python riusciti;
61 artefatti, source e digest binario verificati prima/dopo ogni controllo.
`credit:false`, nessuna compilazione/esecuzione CUDA, nessuna ammissione
congiunta o campagna H100 autorizzata. Il goal rimane attivo.

## Collegamento e parità

`NativeOriginal` conserva W sigillata oppure producer A nello stesso
owner/stream. Il consumer costruisce un packet canonico di EQ MSB e
Cube residuali, prendendo i punti pubblici in prestito e creando una
sola copia canonica per l'upload. Usa la base MAC u³=2, distinta da
PCS v³=v+1. W prepara una sola mappatura per prova; A abbandona il mutex
prima dello scanner. Ogni round visita gli originali una volta.

Begin completa le copie del packet prima di liberarlo; finish legge
cinque Fp3 ed un flag, valida e ritira tutti i buffer privati prima di
pubblicare. Errori terminali non consumano le tre correlazioni del round
incompleto, non usano getter o reader sostitutivi. NoPeek, riserva 3D+2,
MAC originali ed ordine FS rimangono quelli del riferimento.

I 16 casi codec/endpoints comprendono i16, u16 slack residente, split
i48, W ragged, punti zero/uno/extension e Cube duplicati/sovrapposti;
lo zero tail pubblico non causa scansioni. Sono verificati 30 rifiuti,
quattro simboli assenti e cinque fault di avanzamento. La prova D10
signed W, con commitment e PCS CPU, conserva full wire/FS/punto/MAC
contro il riferimento denso. La parità A completa non è implicita in
questa catena; A è coperta separatamente da codec/endpoint e fault.
Le regressioni query e Tree W/A preservano i percorsi precedenti.

L'helper lineare ha 167 casi indipendenti e 218.809 visite, con bench
host D15/D17. L'helper S1 del source `af1a88d` ha 2.304 casi aritmetici,
432 EQ, 41 fasi e 40 rifiuti: è un componente PCS senza owner/caller,
non un risultato S1 integrato. Tutti usano il driver differito o
algebra host, senza eseguire kernel CUDA.

## Risorse, build e failure

Il consumer restituisce 124 B e usa due fence per round; producer e
mapping aggiungono operazioni proprie. Il pinned paga 34 scan A/35 W
senza aumentare le 512 ricostruzioni del commitment iniziale A.
Owner host 37.408 B (+120 B), Stats 152 B, API Rust +32 B; il conto
packet/staging e gli ulteriori costi sono centralizzati nelle
[specifiche](../c7.1/specs.md#closure-e-candidate-aritmetiche).
Non dedurre un picco complessivo da questi subtotal; shared/registri/
spill e margine fisico richiedono hardware.

Build completa preliminare: 58,1051 s, RSS 2.446.405.632 B, picco
aggregato campionato 2.494.259.200 B; un job, O0 crate/O2 dipendenze,
256 codegen unit, LLD con un thread, incremental disabilitato e
overflow checks conservati. La build calda riusa il binario da
92.668.584 B, con digest nel record. I test puliti seriali AS 2 GiB/
60 s hanno RSS massimo 305.885.184 B e wall massimo 43,1015 s.
Non usare Rust O0/modello C++ O2 per rapporti di speedup GPU.

La revisione indipendente ha trovato una fixture che tentava l'upload
di −32768: il valore è ammesso solo come slack. È stata corretta prima
della compilazione generandolo tramite argmax residente, con input
simmetrico separato per il raw i48. I guard di produzione restano
intatti. Il failure documentale preliminare è conservato: quattro
nomi API C venivano scambiati per filtri Rust; la correzione della
notazione non indebolisce i controlli. I log raw restano immutabili.

Restano S1 commitment/OOD/retention/fold, contrazioni private ed aperture
extension residenti, profilo GKR/range/PCG/sincronizzazioni, ledger
completo e preparazione della campagna. I [cinque documenti attivi](../README.md)
mantengono stato e autorizzazione correnti; H100 e durata richiedono
una nuova autorizzazione del proprietario.
