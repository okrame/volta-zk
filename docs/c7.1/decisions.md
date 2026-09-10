# C7.1 — Decisions, exclusions and preserved history

[Status](status.md) · [Design](design.md) · [Security](security.md) · [Evidence](evidence.md)

Si distinguono fallimenti dimostrati della costruzione valutata, linee non
selezionate, requisiti differiti e scelte superate. Un fallimento non si
cancella con una nuova etichetta; una linea non selezionata non è dichiarata
impossibile. L'harness e gli identificatori dei goal esistenti restano invariati.

## Goal dispositions

| Step | Esito conservato e ragione | Fonte completa |
|---|---|---|
| B1 | Chiuso negativamente: riuso WHIR invariato non soddisfa il piccolo contratto C7.1; non esclusione della famiglia WHIR | [B1](../c7.1-gemma31b-design.md#esito-b1-del-riuso-circoscritto) |
| B2 | Port locale CPU/Fp3 funzionale e codec matriciale; tuple LPN diagnostiche senza ammissione di sicurezza | [B2](../c7.1-gemma31b-design.md#b2--port-locale-cpufp3-autorizzato) |
| B3 | Censimento aritmetico/heap e tempi separati acquisiti; traffico fisico completo non misurato | [B3](../c7.1-gemma31b-design.md#b3--censimento-nativo-e-decisione-per-c71) |
| B4 | Ammissione di sicurezza fallita per le premesse del percorso valutato | [B4](../c7.1-gemma31b-design.md#esito-b4-ammissione-di-sicurezza) |
| B5 | Convertitore non verificato escluso; una validità MAC assunta non sostituisce il controllo richiesto | [B5](../c7.1-gemma31b-design.md#esito-b5-esclusione-del-convertitore-non-verificato) |
| B6 | Confronto convertitori concluso; identificato il confine base-sVOLE da verificare in B7 | [B6](../c7.1-gemma31b-design.md#esito-b6-confronto-dei-convertitori-e-confine-del-bootstrap) |
| B7 | Prerequisito OT fallito: la baseline valutata resta fermata. B8 non promuove quel runtime | [B7](../c7.1-gemma31b-design.md#esito-b7-fallimento-del-prerequisito-ot-e-stop-della-baseline) |
| B8 | Selezione di costruzione componibile MR19/P-521 e Wolverine Fp9→Fp3; autorizzazione successiva distinta dalla baseline B7 | [B8](../c7.1-gemma31b-design.md#b8-bootstrap-componibile-selezionato) |
| B9 | Componente nativo e controlli avversari acquisiti; premesse concrete e composizione ancora separate | [B9](../c7.1-gemma31b-design.md#b9-componente-nativo-e-confine-di-ammissione) |
| B10 | Valutazione premesse/lifecycle conclusa senza ammissione; seed-search esclude il vantaggio PRG richiesto per GGM a 128 bit | [B10](../c7.1-gemma31b-design.md#b10-premesse-concrete-e-contratto-di-composizione) |
| B11 | Riparazione locale 128-bit respinta; successivamente selezionato e concluso il profilo finito AES-256 condizionale | [Rifiuto](../c7.1-gemma31b-design.md#b11-esito-del-test-di-riparazione-locale), [selezione](../c7.1-gemma31b-design.md#b11-selezione-intermedia-aes-a-capacità-finita) |
| B12 | Goal matematico same-W/KV/ZK congiunta chiuso a `9e57199`; percorso nativo ridotto completo verificato con MAC ideali, port canonico/AES aperto | [Prova corrente](security.md), [evidenza nativa](evidence.md#native-bounded-composition), [prossimo lavoro](status.md#next-goal) |

I vecchi limiti di commit e stop della fase B1 non si riapplicano come
nuovi gate a B12. Il rifiuto B7 rimane invece effettivo per quella baseline.
I campi legacy del budget continuano a descrivere il loro oggetto: un
`security_admitted:false` storico non nega il successivo teorema condizionale,
e il completamento matematico non rende quei vecchi componenti ammessi.

## Excluded constructions and reusable lessons

| Costruzione o argomento | Disposizione precisa |
|---|---|
| Riuso della maschera split e colonne del carrier G1 | Controesempi di privacy/size per il codec e i parametri espliciti; non lower bound per ogni PCS |
| Hash binario esplicito / replay generico G2 | Costi e letture esclusi per quelle realizzazioni; non si nascondono sotto «GKR gratuito» |
| Coupling interattivo trasferito direttamente a FS | La prima query a un candidato non pubblicato rompe quella premessa; B12 conta prefissi/candidati/preprocessing, non assume indipendenza condizionata al successo |
| A3 con composizione letterale IBCS/256 bit | Esclusione del bound specifico e gap expected-time documentati; non impossibilità di RS ricorsivo |
| GGM 128-bit con label nuove o rinnovi | Non risolve il seed-space lower bound B10/B11, neppure con un solo output osservato; non è un attacco completo al PCG/matrice |
| Root non salata a esaurimento dei pad | Perdita di privacy dimostrata; B12 usa Merkle salato e budget congiunto delle esposizioni, non pad illimitati |
| WHIR/Ligero monolitici per W e B12 denso D35/D34 | Materializzazioni escluse dai limiti di memoria; una dimostrazione matematica con decoder/trace densi non concede uno schedule fisico |
| Reader che cambia quantizzazione, raw o endpoint | Non preserva lo stesso valore; range dei byte o una nuova autenticazione valida non provano RNE, predecessore o W originali |

Le dimostrazioni e i parametri dei controesempi rimangono nei dossier
mappati sotto. Riusarne un componente richiede verificarne le premesse;
nessun vecchio margine di memoria o sottototale si trasferisce automaticamente.

## Unselected research

**G2 è archiviato e non è un goal in coda.** Restano utili il coupling NoPeek,
la sorgente fissata prima delle richieste, le promozioni solo dopo verifica
e il controesempio della prima query FS. Il [riuso nella prova attuale](security.md#6-risorse-riuso-formale-e-confine-runtime)
non assume risolti gli obblighi PCS/FS/fisici di G2.

A5 wide-hash resta un riferimento di ricerca non selezionato, senza nuova
crittanalisi da avviare né una dichiarazione di rottura. Si conserva la scelta
BLAKE3 del percorso corrente. La candidata silent alternativa a B11 non è
selezionata. Nessuna di queste linee si riattiva per aggirare un costo ignoto.

## Deferred requirements and options

- Rinnovo di root/correlazioni, recovery da abort, reopen/riavvii, nuove chat
  indipendenti e lifetime multi-epoch: fuori dal run selezionato. In un'eventuale
  estensione tutte le root devono comunque legarsi allo stesso W; un nuovo
  setup o una label non concede capacità o privacy illimitate.
- Calibrazione/qualità Gemma, provenienza dei pesi e confronto BF16, full E2E,
  contesti fino a 4.096 e schedule fisico: obblighi successivi distinti dalla
  corrispondenza nativa su grafi piccoli. Non sono prestazioni acquisite.
- Cinque letture W o circa 20 GB di spill host: opzioni da confrontare se
  migliorano il tempo completo. Contare scrittura+rilettura, calcolo evitato,
  staging e overlap dimostrato; il riferimento resta quattro letture/no spill.
- Profilo ibrido INT16 GEMM con BF16/FP32 per non-lineari: non adottato.
  Richiede stesso checkpoint/dati/tokenizzazione, confronto qualità/costo e
  semantica provata di cast, RNE/FMA, subnormali, non-finiti e KV. Il
  [controesempio FP32](../c7.1-gemma31b-design.md#2-identità-del-modello-e-pezzi-riutilizzabili)
  impedisce di trasferire RMS intera a riduzioni float diverse.
- Due letture W, ottimizzazioni aritmetiche e diagnostiche GPU: opportunità
  documentate, non prerequisiti da anteporre al prossimo port e non spesa
  autorizzata. Qualunque scelta va valutata sul tempo e costo completi.

## Superseded profiles

| Profilo o stato precedente | Interpretazione corrente |
|---|---|
| Obbligo aperto «comporre same-W/KV/ZK» | Scaricato per l'algoritmo matematico in security; percorso nativo ridotto verificato, trasferimento al dispatcher canonico e al pool reale ancora aperto |
| «Ricetta softmax da scegliere» | `C71-SOFTMAX-EXP30-v1` selezionata; non equivalenza alla softmax reale |
| Lifetime S20, memoria del riduttore M89, 27 risposte/32 slot | Derivazioni precedenti; profilo attuale S=1, M93 e tre tentativi, senza rinnovi |
| B2 matrice, A5/S e R3/S+Y/altre estensioni incrementali | Profili/componenti distinti, non parti indipendenti da sommare al B12 finale |
| Geometrie ausiliarie D31/D33 e target/cubi parziali | Sostituite dal layout finale Flat(D34), produttori comuni e batch completo di security §3 |
| Circa 91 bit della matrice o 82,99 bit dei primi operatori | Bound dei loro sotto-protocolli; il risultato completo è nello stato e in security |
| 11.187.057 righe del preflight | Conta specifica con placeholder; non sostituisce l'upper conservativo o la certificazione numerica |
| Vecchio 125% per sotto-codec W / 480 terminali / 472 usi | Riferimenti D126, non quote o numeratori imposti alla relazione nuova |

## Archive and migration map

Cinque documenti attivi sostituiscono il ledger e il design cumulativi.
I vecchi percorsi dei dossier sono conservati per non rompere fonti,
script e citazioni; l'indice li classifica come derivazioni storiche.
Questo evita copie attive concorrenti e una rinomina a cascata dell'harness.

| Documento precedente | Sede corrente / contenuto preservato |
|---|---|
| `prototype-status.md` | Ingresso compatibile verso [status](status.md), con tutti i vecchi anchor. Corpo integrale nel [nuovo snapshot](../prototype-status-history-2026-09-10.md) |
| `c7.1-fixed-run-composition.md`, §§1–6 | Testo integrale trasferito in [security](security.md), salvo percorsi dei link; vecchio file è solo navigazione compatibile |
| `c7.1-gemma31b-design.md`, apertura e §§1–4 | Requisiti riconciliati in [design](design.md); vecchia prosa conservata integralmente nel notebook congelato |
| Stesso notebook, §§5–6 | Derivazioni algebriche/FS storiche; il riuso corrente è esplicito in [design](design.md#assumptions-and-component-dependencies) e security |
| Stesso notebook, §§7–9 | Contratto risorse corrente in design; conti, confronti CPU/GPU/OpenLLM/DeepProve e opzioni originali restano integralmente nel notebook |
| Stesso notebook, §10 B1–B11 | Esiti sopra; derivazioni, mandati al momento della decisione e link dei record restano nel notebook |
| Stesso notebook, §10 B12 fino alla chiusura | Dipendenze della prova e port componenti mappati in design/evidence; successione completa di correzioni e sottoconti nel notebook |
| [G1 feasibility](../c7.1-feasibility.md) | Criteri, carrier, split-mask e controesempi di size; evidenza circoscritta, non gate attivo su tutto B12 |
| [G2 committed MAC](../c7.1-committed-mac-opening.md) | Linea archiviata non selezionata; riuso NoPeek/FS esplicitamente delimitato sopra |
| [A3 recursive RS](../c7.1-recursive-rs-opening.md) | Encoder/ricorsione, binding ideale, audit IBCS e costi/esclusioni |
| [A4 paired RS](../c7.1-paired-rs-opening.md) | Arbitrary-fold, forme dyadic, riduzione a due visite e premesse di composizione |
| [A5 wide hash](../c7.1-wide-hash-opening.md) | Parametri pubblici, ipotesi hash, trail, costi W/KV e liveness; non selezionato |
| [W-cut witness](../c7.1-cut-witness.md) | Replay/P0/route, semantica RMS/Q30/GELU e conti condizionali; riuso numerico esplicito nel design |
| [R1 requantization](../c7.1-requantization.md) | i16/byte, RNE esatta, range e riparazione del reader/PCS |
| [R2 RNE indicators](../c7.1-rne-indicators.md) | Funzioni grado 7, P/S e sei byte, esclusioni di replay/arena |
| [K1 KV transition](../c7.1-kv-transition.md) | Viste temporali, concat/prefix e MAC originali; la validità delle code è ora scaricata dal teorema composto |
| [T1 attention products](../c7.1-attention-products.md) | QK/PV/GQA e Pi originale, riduzioni rettangolari e costi locali |
| [R3 auxiliary witness](../c7.1-auxiliary-witness.md) | Estensioni di sorgente/reader/encoder e liveness progressiva; non sommare profili alternativi |

Gli undici dossier G1/G2/A3/A4/A5/W-cut/R1/R2/K1/T1/R3 restano byte-per-byte
invariati. Il notebook conserva il corpo di `9e57199` con una sola avvertenza
iniziale; SHA-256 del corpo originale:
`bb3af4cfbce53f00ae90ebfe87862003dfe9817168669a48383801e714516d2a`.
Il nuovo snapshot del ledger è identico all'originale, SHA-256:
`ee535a27757b8796357c54258438e4186eaf1f9c1248d4fa80f22e7b58e3cf03`.
La prova originale è recuperabile anche a `9e57199`, SHA-256 del vecchio file:
`e2905f3ef174ef54fc00a5d84e553891e0466d075211762172489dffdff1b88b`.
Fonti sotto `sota`, benchmark, vecchi snapshot e milestone formali congelati
non sono stati modificati. Gli aggiornamenti futuri riguardano i cinque
file attivi; gli archivi non tornano a essere ledger concorrenti.
