# C7.1: chiusura della campagna H100 — 10 ottobre 2026

Campagna conclusa con **zero certificati canonici accettati**. Il percorso
O=0 raggiunge W, setup, preparazione e parte del commitment A; O=150/300
non iniziano. Il pod `z6wx2kkn69eoc0` è confermato **EXITED, runtime assente**
alle **01:49:55 UTC (03:49:55 Italia)**, dopo
**6 h 41 min 12,8 s** dall'avvio provider conservativo,
entro il massimo autorizzato di otto ore. Il
[record di chiusura](../../benchmarks/results/c71-h100-campaign-close-2026-10-10-304e0d74d5a9.json) conserva ricevute provider, deadline,
ritiro del guard dopo conferma, verifiche hash e collegamenti ai record originali.

## Risultati e limiti

| Fase | Misura | Ambito |
|---|---:|---|
| Caricamento W | 61,543 s | Sesto trial, prima della residenza CUDA |
| Residenza nativa W | 22,723 s | Sesto trial, separata dal commitment |
| Installazione W | 212,418 s | Comprende PCS W 190,425 s; non sommare gli intervalli annidati |
| Setup AES | 1.493,833 s verifier; 1.493,832 s prover | Ruoli simultanei, tempi non sommabili; 61.841.366 B applicativi bidirezionali |
| Inferenza O=0 separata | 84,382 s | Tutti i 150 token uguali al replay intero ammesso |
| Preparazione O=0 canonica | 85,021 s | Comprende inferenza e validazione, sesto trial |
| Prova completa | Non misurata | Stop prima del completamento A |
| Verifica completa | Non misurata | Nessun certificato acquisito |

Il [sesto trial](h100-canonical-06-2026-10-10.md) termina dopo 35/512 gruppi A:
**6.560.767.488 B** temporanei simultanei campionati contro
**6.174.015.488 B**, eccedenza 386.752.000 B. Il payload sotto cap non
ammette il picco fisico. Fra gli ultimi due campioni host/esenzioni W
sono invariati e l'uso GPU cresce di 504 MiB; la causa resta aperta.
Il [terzo diagnostico A](h100-a-quarter-2026-10-10.md) con code ridotte
fallisce a 6.441.455.104 B, dopo 22 gruppi.

L'[ultimo diagnostico A04](../../benchmarks/results/c71-h100-a-component04-2026-10-10-47af19bbe888.json) termina per **cap fisico dopo 86/512 gruppi**, wall 780,205 s.
Usa code compute/copy 1/1, scala 0,25 e lanci sincroni, stessa libreria
sm_90, geometria D34, 512 ricostruzioni e monete PCS nuove. Il massimo
stabile campionato è **6.535.814.656 B**. È un componente senza commitment
W, setup, prova MAC, verifica o continuazione: non dimostra il picco
canonico e non cancella i fallimenti precedenti. Lanci sincroni restano
una configurazione diagnostica, senza selezione di produzione.

Il target **65 s** resta non raggiunto: la sola inferenza misurata lo
supera. I timeout diagnostici più lunghi permettono osservazione e diagnosi;
non cambiano il target. Le durate mancanti sono `null`, mai zero.

## Guadagni osservati e lavoro residuo

- Accumulo W su fixture 256 MiB: **5,663×** (45,477 → 8,030 ms), con
  confronto completo all'oracolo CPU. È un componente sintetico.
- PCS W completa: primo trial 360,301 s, sesto 190,425 s; installazione
  404,340 → 212,418 s. Sono run singoli con configurazioni diverse,
  senza attribuzione isolata. Il caricamento W varia e resta separato.
- Coda cGGM differita: **1,475×** nel microbenchmark; setup completo
  precedente 1.986,453 → 1.493,833 s, **−24,799% / 492,620 s** osservati.
  Il precedente setup sovrappone circa 64 s a controlli CPU indipendenti:
  non è un confronto causale isolato. Traffico e capacità restano invariati; le correlazioni di ogni trial sono nuove.
- Inferenza esatta: 90,615 → 84,382 s, **−6,879%**
  osservato; temporanei campionati 1.474.276.864 → 1.216.531.968 B,
  **−257.744.896 B** nello stesso ambito di componente. Nessun credito al
  picco canonico. Il batching del prompt a 132,036 s è stato ritirato.

Restano il superamento fisico durante A e le 512 ricostruzioni complete;
poi occorre misurare l'intera prova/verifica, oggi non raggiunta. Il ledger
RMS indica analiticamente 844.006.203.160.300 moltiplicazioni Fp3 CPU e
998.927.195.904 callback per risposta: è uno schermo analitico, non un tempo
completo. Anche la comunicazione conserva un esito negativo nel conto
specificato: il [conto composto](../../benchmarks/results/c71-h100-communication-composition-2026-10-09-a885e07a0ada.json)
unisce un prefisso misurato e un corpo inferiore analitico, senza spacciarli
per certificato misurato. Il bound iniziale bidirezionale è 134.174.406 B;
quelli di continuazione sono 54.869.487/61.798.553 B, da confrontare con
130/40 MB nello stesso ambito. Nessun cap parser è stato modificato.

## Identità, controlli e conservazione

Base `c7e05cf`, correzioni operative `24b54d4`, branch
`runpod/z6wx2kkn69eoc0/c71-h100-20261009`. Γ ammesso riusato dopo cinque
controlli, identità, ricette, tabelle e tre piani pubblici esatti. I sette
input selezionati sono stati trasferiti senza nuova calibrazione. Shard e
packed non erano presenti: download unico 623,544 s e ingest 490,419 s,
con hash verificati; poi W sigillato riusato in tutti i trial. I binari
locali ARM64 erano incompatibili: compilazione x86_64/sm_90 sul pod,
CUDA 12.8.93, GCC 13.3 e Rust 1.96.1. Il digest immagine non è disponibile.

Passano i 15 test sulla libreria CUDA reale, ripetuti per le configurazioni
selezionate e prima del diagnostico sincrono, più il controllo non lineare.
Le correzioni operative includono build/linkage CUDA, processi che terminano durante la lettura procfs,
marker pubblici non selezionati, limite degli span al prefisso KV scritto,
telemetria terminale e cGGM. Il test del prefisso fallisce prima e passa
dopo sullo stesso binario della fixture; coda non scritta e overflow
restano rifiutati. Localmente: 36 test monitor, due owner Python, nove
controlli documentali, regressioni Rust mirate; nessuna build formale nuova.

NoPeek, numerica, MAC originali, dominio/transcript, monete fresche e
PCG AES sono preservati. Non sono state riusate correlazioni: farlo
avrebbe cambiato le garanzie richieste. Le capacità di ogni trial terminale
restano bruciate; nessuna sessione viene ripresa. Parità finita non chiude
il raffinamento CUDA/Seed6 né l'invariante generale del prefisso C++,
esplicitati nel design attivo.

Fallimenti, timeout, stop pianificati, letture smaps fallite e candidati
ritirati rimangono nei record originali. Gli export incrementali hanno
manifest immutati e hash verificati; il record finale riferisce la verifica
di integrità. Input Γ e tabelle restano locali. Shard/packed e grandi tracce
sono esclusi dalla conservazione, come da tetto cumulativo 10 GB: hash e
ricette non equivalgono a conservarne i corpi. Nessun peso, segreto o pool
di correlazioni è pubblicato. Il trasporto sorgenti è Git HTTPS; la [deviazione
SSH iniziale](h100-monitor-stack-2026-10-09.md) è conservata e verificata poi via HTTPS.
Il guard è stato ritirato solo dopo conferma provider. La campagna è chiusa;
nuovo hardware o nuova durata richiedono una nuova autorizzazione.

Un [errore di invocazione del helper documentale](../../benchmarks/results/c71-h100-campaign-close-2026-10-10-304e0d74d5a9/docs-helper-invocation-failure.json)
è conservato: percorso relativo rifiutato prima di scrivere, poi invocazione
corretta con percorso assoluto. Nessun run o spegnimento è stato ripetuto.
