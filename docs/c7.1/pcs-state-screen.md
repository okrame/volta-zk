# C7.1 — PCS e stato persistente: candidata, non ammissione

2026-09-11. [Stato](status.md) · [Design](design.md) · [Evidenza](evidence.md).

## Risultato e criterio del proprietario

La variante studiata combina PCS con parametri ridotti, RNE in gruppi senza
padding aggiunto e KV cumulativo nel nuovo snapshot. Il solo KV cumulativo
non risolve il lifetime di W: il commitment B12 installato ha tre esposizioni.
Si distinguono quindi due costruzioni, entrambe **non selezionate**:

| O | B12 attuale, upper | KV cumulativo, W a tre esposizioni | KV e W entrambi collegati al predecessore |
|---:|---:|---:|---:|
| 0 | 65.053.244 | 27.408.344 | 26.686.168 |
| 150 | 78.945.726 | 34.669.384 | 41.157.548 |
| 300 | 92.723.304 | 34.669.384 | 41.157.548 |
| PCS per risposta | 2 / 3 / 4 | 2 / 3 / 3 | 2 / 4 / 4 |

Sono **upper condizionali del wire della risposta**, con corpo, RNE, range,
maschere, sali, frontiere Merkle massime, header, frame e chiusura. Non sono
certificati Gemma validi misurati. I lower corrispondenti della seconda
variante sono 17.857.848 / 26.835.276 / 26.835.276 byte e conservano le
omissioni del lower B12: GKR congiunti e hash fratelli. Il lower non è un
obiettivo raggiunto. Bootstrap/offline e setup restano voci separate da
misurare e contare una volta nel confronto della conversazione completa.

La seconda variante evita anche il budget di maschere W lineare nel numero
di tentativi pianificati, ma paga una PCS W aggiuntiva dopo il primo turno.
Non è dimostrato un minimo globale: lo screen visita soltanto 60 geometrie.
Il minimo wire della famiglia usa 448 query; il componente nativo studiato
ne usa 456. Il margine di questo screen PCS non sostituisce il bound completo.

**L'obiettivo del proprietario resta aperto:** manca la verifica di lavoro
totale non crescente e la composizione di sicurezza della candidata. Non
si deduce quella verifica dalla riduzione di byte, correlazioni o FFT.

## PCS: cambiamento circoscritto

Si riusano l'IOP CFW, il consumer claimless, la chiusura sul MAC originale,
Goldilocks/Fp3, Merkle salato e la disciplina FS B12. La fonte primaria è
[CFW 2026/391](https://eprint.iacr.org/2026/391), già conservata come
[Markdown AnyDoc](../../sota/2026-0391-zero-knowledge-iopps-constrained-interleaved-codes.md).
La fonte dimostra HVZK dell'IOP; il trasferimento al verifier malevolo/FS
rimane quello da ricomporre, non una proprietà acquisita citando il paper.

| Parametro | B12 | Candidata |
|---|---|---|
| Query per oracolo/maschera | 512 | 456 |
| Fold D34/D35 | 7, poi 2 | 6, poi 4 |
| H per M coefficienti e r pad | nextpow2(8(M+r)) | nextpow2(4(M+r)) |
| r iniziale | 1536 | 1368 per tre esposizioni; 912 per due |
| r successivo | 512 | 456 |
| ell comune a tutte le maschere della PCS | 2048 | r iniziale + 1 |
| Dominio maschere | 32768 | 8192 |

`H>=4(M+r)` implica `H-(M+r)+1>3H/4`: rimane la premessa MCA
`3*tau<d`, con tau=H/4, senza congetture di lista. Restano dominio
Goldilocks <=2^32, codice comune delle maschere, pad sufficienti per
l'unione delle esposizioni e una coordinata per l'OOD. Il censimento usa
gli errori dei veri blocchi B12, incluso
`(1-1/(4G))^(G*t)` per query indipendenti dei gruppi; non sostituisce questo
termine con `(3/4)^t`. Arrotonda i razionali verso l'alto a 256 bit.
Il termine PCS isolato `Q* max(delta_blocco)` è sotto 2^-87; non è la
soundness completa della nuova schedule.

Le PCS della prima variante hanno intervalli wire:
W/D35 5.157.568–7.932.608, A/D34 4.434.784–7.136.864 byte.
Il codec canonico con questi parametri è controllato con fixture sintetiche.
Il test positivo su D12 verifica invece PCS effettive, MAC originale,
digest FS, troncamento e target falso, per tre/due esposizioni della root.
Non esegue una prova linear/Gemma completa. Il primo tentativo di test D10
con fold 1→4 è stato respinto da `RateGrowsDomain`; D12 usa 4→4. Non si
attribuisce il successo D12 alla geometria D10 respinta.

## KV cumulativo e, separatamente, rinnovo W collegato

Preparare A_j prima delle sfide, includendo una copia del KV già accettato
oltre alle sorgenti correnti. Ciascuna copia ha un layout pubblico: layer,
K/V, posizione, head, canale e byte. Il KV dell'ultimo token è incluso.
Il verifier conserva soltanto il predecessore completo necessario alla
transizione e l'identità dell'installazione; non importa ricevute del peer.

Dopo C_Aj, campionare un punto r sul vettore byte concatenato del KV
precedente. Autenticare una sola volta z, valutazione del vecchio KV, e
inserire **lo stesso MAC** in entrambe le PCS, con le rispettive forme:

```text
L_prev(r, A_(j-1)) = z = L_copied_prefix(r, A_j).
```

Un'alterazione fissata prima di r dà un polinomio multilineare non nullo;
la perdita interattiva è al più d/q. Nel ROM occorre addebitare il nuovo
blocco ai prefissi/candidati globali, insieme a PCS e MAC. Gli endpoint
QK/PV leggono tutto il KV da A_j; la coda nuova viene ancora dai produttori
originali. Non basta un hash del KV o un MAC libero. L'induzione same-W/KV
usa le sole promozioni dopo verifica completa; abort e fallimento terminano.

Il vecchio KV aggiunge 0 / 344.064.000 / 688.128.000 byte logici ad A.
I live totali diventano 13.154.672.538 / 14.678.384.538 / 16.202.096.538:
ancora D34 per questi tre contesti. Copia, getter, forme e range non sono
gratuiti. Anche conservando pagine immutabili con alias, letture e lifetime
vanno conteggiati e il predecessore resta vivo fino alla promozione.

Per la seconda variante, dopo il primo turno preparare anche un commitment
W_j fresco e indipendente da Delta. Un secondo MAC condiviso lega una
forma casuale dell'intero W_j a W_(j-1), padding incluso. I produttori
usano W_j; la catena verificata mantiene l'identità del W installato.
Ciascuna root W ha al più due esposizioni: uso corrente e collegamento
al successore. Non riutilizzare correlazioni, pad o maschere di proof.
La tabella paga entrambe le PCS W, il nuovo MAC/frame e 128 byte riservati
ai metadata delle root di lavoro, oltre al collegamento KV. Sono riserve
di uno schema proposto, non framing nativo completo già implementato.

Il numero di PCS diventa costante. Con un blocco nuovo fissato, la loro
geometria e quella dei sumcheck crescono con il logaritmo dei domini al
crescere della storia. **Non è una prova di lifetime illimitato:** capacità
AES, query RO, risorse delle riduzioni, layout e cap dei kernel richiedono
un profilo finito esplicito. Non si estrapolano i tre test a 4.096 token.
Se crescono invece i token nuovi, la lista dei token impone già almeno
4 byte per token nel codec corrente: i byte completi non sono sublineari
in quella quantità, né nel totale cumulativo di tutte le risposte.

## RNE: eliminare il padding aggiunto prima di confrontare il lavoro

Il batch a due gruppi precedente aggiungeva 2.634.022.912 / 1.627.389.952 /
1.627.389.952 celle byte, ciascuna con 256 foglie P/S. È un aumento reale
del lavoro della sua implementazione densa, non compensato automaticamente
dalle 839.615–841.535 righe Fp3 eliminate.

`unpadded_groups` ordina stabilmente per dimensione e riempie blocchi
diadici esatti. Ogni richiesta originale appartiene a un solo gruppo;
non spezza endpoint o tabelle e non aggiunge celle:

| O | Bit dei gruppi | Byte P/S con frame |
|---:|---|---:|
| 0 | 34,32,30,29,25,24 | 214.116 |
| 150/300 | 34,32,31,28,27,26,25,24 | 280.208 |

Il sovrapprezzo rispetto ai due gruppi è 133.240 / 199.332 byte, incluso
nella tabella iniziale. Il numero di foglie e nodi dei 256-entry alberi
rimane quello separato; resta da addebitare il sumcheck iniziale aggiunto,
le forme, il routing e lo schedule. La sola uguaglianza del numero di
foglie non dimostra lavoro totale uguale. Il kernel condiviso resta test-only.

## Lavoro completo: confronto richiesto, ancora non scaricato

Lo [screen eseguibile](../../scripts/c71_pcs_state_screen.py) conserva
`full_prover_work:null` e `full_work_nonincrease_verified:false`.
Conta geometrie logiche per encoding e butterfly radix-2, distinguendo
campo base ed estensione. Per W con tre esposizioni l'encoding iniziale
scende da 549.755.813.888 a 274.877.906.944 celle base e da
8.796.093.022.208 a 4.398.046.511.104 butterfly. A dimezza anch'essa
l'encoding iniziale. **Non sono tempi o conteggi completi del backend.**

Il confronto necessario è per ogni prefisso della stessa conversazione:

```text
setup + tutti i commit/rinnovi + inferenza + preparazione witness
+ RNE/GKR/range + PCS/fold/FFT/hash + PCG + replay
+ serializzazione + scritture/letture/trasferimenti delle cache.
```

Il prover attuale rimaterializza la root in `prove_pcs`, oltre a crearla
nel setup. Nel run di T risposte ciò dà 1+T encoding iniziali W e
T+T(T+1)/2 encoding A. La variante con entrambi gli stati mobili, senza
riuso dei dati di commit, ne dà 3T-1 per ciascuna famiglia: **W aumenta**
da 4 a 8 esecuzioni a T=3, pur con encoding più piccolo. Non basta
mostrare il costo di una singola PCS. Anche gli hash/sali per riga possono
avere un rapporto diverso dai byte dei codeword.

La memoria persistente fuori H100 autorizzata dal proprietario permette
di studiare la conservazione dei dati iniziali di commit fino all'ultimo
consumer. Non permette di saltare copie, trasferimenti, nuovi pad, proof
fresche o il costo di creare quella cache. Lo schedule corrente consuma
i dati del prover: non c'è qui un'implementazione di cache a costo zero.
Rimangono invariati H100, arena, trust model e assenza di autorizzazione
a run pesanti/provider. I dati canonici non vengono materializzati localmente.

Prima della selezione servono quindi contabilità completa con disuguaglianza
contro la baseline, composizione ROM/ZK/risorse, routing canonico e prova
completa valida. I lemmi `Mac.Valid.add/smul/sum` e l'induzione KV già
citati in [security §6](security.md#6-risorse-riuso-formale-e-confine-runtime)
supportano le identità; non dimostrano da soli questa nuova costruzione.
