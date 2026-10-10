# H100: diagnostico del commitment A — 10 ottobre 2026

Il [record](../../benchmarks/results/c71-h100-a-component01-2026-10-10-3ea1e4a82d07.json)
usa la nuova CLI `commitment-a-cuda` della checkout pulita `3ea1e4a`.
La build H100 impiega 287,131 s / RSS massimo campionato 1.785.901.056 B.
La libreria `a32a6c3` è riusata con hash verificato e sorgenti CUDA,
owner e PCS identici alle precedenti parità reali; il record conserva
questo riuso, non dichiara una nuova serie di 15 test.

Il diagnostico parte alle 00:11:25 UTC e termina dopo **317,531 s**, exit 1,
con **`native range stopped: PCS original source tile or state`**.
Nessun timeout, stop manuale o violazione fisica: massimo campionato
5.994.184.192 B, payload 5.554.384.680 B, zero swap/errori smaps.
Il caricamento W impiega 189,297 s e la residenza nativa 20,990 s.
Il record conserva separatamente la preparazione e il commitment fallito.
Non si misura inferenza autonoma dopo un'accettazione inesistente.

Il percorso usa la preparazione originale O=0 e il commitment A D34,
quattro coset/tutte le 128 colonne e 512 ricostruzioni, con nuove monete
PCS generate dopo la preparazione NoPeek. Mancano deliberatamente W PCS,
setup AES, prova, verifica e continuazioni: è un componente senza credito,
non una risposta canonica né una scorciatoia certificabile.

L'ispezione individua una guardia che richiede `initialized == count`
per ogni sorgente originale. KV riserva 450 token ma dopo O=0 soltanto
150 sono scritti. Il gather di byte già valida il prefisso scritto;
PCS iniziale, closure lineare e residual richiedono invece capacità piena.
La candidata corregge il limite degli span a `initialized`, mantenendo
terminali letture oltre il prefisso e gli altri controlli di identità,
tipo, copertura e valore. Il nesso col precedente `Stop` uniforme di C05
è una deduzione da codice e riproduzione, da confermare dopo la correzione.
Non si cambia Γ, A originale, MAC o capacità dei buffer.

Bundle privato `h100-final-a-component01-20261010T001700Z`, 25 file,
9.985.564 B, manifest SHA-256
`d267c7622dc999b0e13ba17597897da0c0b764493933393578486046df42009c`.
