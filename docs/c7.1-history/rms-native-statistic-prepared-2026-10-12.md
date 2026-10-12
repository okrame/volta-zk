# RMS statistica GPU — consumer candidato, verifica pendente

Dopo la parità byte originale, è scritto il consumer di `S=ΣX²` sullo
stesso P0 cubico, con wire/FS/MAC e apertura X/S originali. Codice
non ancora compilato/eseguito. Default canonico invariato; ingresso
statistica+byte completo solo nel caller sperimentale cfg(test).

Il consumer raccoglie una volta gli i16 originali della vista selezionata,
row-major, e li registra readonly/mapped. Zero nelle righe/colonne di
padding, nessuna copia Fp3(N) o Eq(N). Query e prefissi restano nel
consumer, nessuna moneta/MAC passa al producer. Stato unweighted entro
8MiB, checkpoint pubblico e Eq fattorizzata senza divisioni; fold MSB.
Per X=W gli stessi cubici sono ottenuti dal primitivo fraction-tree
con figli(0,X,0,X), λ=1, poi chiusi sugli endpoint P0 originali.

Lo staging dinamico riusa rms.window/shadow/publication, active4; nessun
puntatore C++ aggiuntivo, owner ordinario atteso42.504B invariato.
Token privato kind20, guard su geometria, ordine/prefisso, owner e alias
con sorgente immutabile. Flag/fence/free/unregister incerti non pubblicano
output; Arc e addebiti sopravvivono a cleanup incerto. Terminale unico
dopo ritiro, incluso1×1/bits0. Tre simboli opzionali fino a selezione,
poi mancanti/esecuzione indisponibile causano arresto, senza fallback.

P0 ha ora un unico writer con callback fallibili per coefs/terminale.
Il percorso denso originale conserva gli stessi valori e ordine FS:
fold all’ingresso del prossimo round/terminale, capacità Vec invariata.
Test del fallimento prima dell’autenticazione,25 rifiuti owner, API
mancanti/owner estraneo, tre domini GPU (ragged e checkpoint effettivo),
wire/verificatore/tamper e caller RMS/PCS sono preparati ma pendenti.
Le nuove API non sono selezionate dal dispatcher canonico.

Premesse: linearità MSB del fold, Eq fattorizzata/somma unitaria,
quadrato del polinomio folded nello stesso P0, fonte deterministica
e immutabile, codec signed-i16 LE, lifetime/capacità/fence CUDA e
allowance driver. Sono obblighi di raffinamento implementativi, non
nuovi lemmi Lean; test finiti non li scaricano. La fonte normativa
resta [specs](../c7.1/specs.md) e [security](../c7.1/security.md).

Prima di qualsiasi selezione servono compiler/owner/GPU originale e
conto simultaneo incluse sorgente host, page slack, Eq/state/partials,
metadata e driver. La fonte raw massima8192×5376×2 e lo stato8MiB sono
upper locali, senza ammissione o tempo canonico. Nessun nuovo AES,
certificato o journal; O=0/150/300 aperti. VM solo editing/controllo/hash,
calcoli/build/test sul pod autorizzato entro13:19:04 UTC.
