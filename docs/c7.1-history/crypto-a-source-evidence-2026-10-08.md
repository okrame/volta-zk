# Evidenze del consumer PCS A — 8 ottobre 2026

Source commit `98ac67808e29fd421d138bd66f6c1c4fa9307866` sul branch dedicato
`task/c71-h100-crypto-20261008`, successivo a `970378a`. La
[decisione del componente](crypto-a-source-2026-10-08.md) rimane una
fotografia del checkpoint preliminare; questo receipt aggiunge la misura
pulita senza modificarla o correggere record raw precedenti.

Il [record locale](../../benchmarks/results/c71-crypto-a-source-local-2026-10-08-98ac67808e29.json)
ha SHA-256 `47ef30b62d423a5b6f423fb13a1abfeb4425f9e76d691bf43b5196b8bb53764f`,
`git_dirty:false`, 13 test Rust e undici Python passati. I 62 artefatti
conservano log/report, runner, misure preliminari, la build con errore
dell'oracle Merkle e il test con assunzione errata sul replay dopo
promozione. Tutti i digest/dimensioni sono verificati dal generatore.

Ogni test usa 60 s/AS 2 GiB, un worker, processi seriali. Massimo RSS
test/compilatori discendenti 247.549.952 B; payload congiunto massimo
del componente ridotto 4.965.787 B. La build completa preliminare richiede
55,84 s/RSS 2.482.995.200 B separato. Cargo sul tree pulito termina in
0,17 s e riusa il binario identico: il record espone questo riuso, il
digest del binario e i digest degli input, senza presentarlo come una
nuova compilazione completa pulita.

Parità completa campo per campo e dei digest su tre geometrie, istogramma
esatto e 28 rifiuti terminali. Lo scanner pruned Affine/RNE emette
6.451.200 byte tramite 36 descrittori: nessuna riga scaricata, soli otto
byte di flag. La verifica dei descrittori e quella degli accumuli sono
componenti distinti, non una prova canonica composta del producer/PCS A.
Sono positivi anche codec, permutazione, byte gather e Tree W/accumuli,
FFT, hash, errori e risorse sullo stesso owner aggiornato.

Il conto A canonico conservativo è 5.578.870.016 B prima degli altri
owner host, lasciando 326.710.016 B nel payload comune. L'owner host da
37.152 B corregge W di +88 B rispetto al record Tree precedente:
4.611.875.360 B. Conti e raw precedenti rimangono immutabili. Sono screen
`credit:false`, non un'ammissione del picco fisico o del percorso completo.

Tree/runner A non selezionano ancora il componente; A resta a 512
ricostruzioni e PCS CPU. Rimangono integrazione root/seek/aperture/
transcript/MAC, conto completo degli altri owner, confronto Tensor Core W,
sampler e resto della prova. La VM non compila CUDA; non è acquisito tempo,
picco o parità H100. Il goal rimane attivo e non richiede nuova hardware
finché la preparazione locale non è completa. La campagna futura richiede
nuova autorizzazione del proprietario per hardware e durata.
