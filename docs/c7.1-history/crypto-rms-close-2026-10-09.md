# C7.1 — replay RMS e chiusura locale, 9 ottobre 2026

Checkpoint storico; istruzioni correnti nel [design](../c7.1/design.md).
Il [record finale](../../benchmarks/results/c71-crypto-rms-local-2026-10-09-abd2de09efb4.json) conserva sorgenti pulite, build,
digest del binario, log positivi/negativi e conto conclusivo. Il source
finale verificato è `1b625db4552ae7acc6855e82c8d63e44e9a78aff`;
`ba23132` aveva già i positivi cache/packed, ma non la nuova fixture
completa e la separazione delle schedule. Nessuna esecuzione CUDA o H100.
Γ pinned è riusato: nessuna nuova scala, semantica o ammissione numerica.

## Cambiamento selezionato

RMS misto valuta gli stessi circuiti Booleani con `PackedReplay` a 64
lane e DAG per depth. Applica il percorso soltanto a
`pattern_prefix.is_none() && programs.len()>1`; statistic e pattern
singoli conservano la schedule precedente. Frame, indice di cella,
ordine dei programmi, alias, wire Copy e padding rimangono quelli del
caller. Non sono introdotti istogrammi, correlazioni o sfide nel replay.
Il primo round usa un calcolo esatto degli stessi coefficienti.
La cache conserva chiavi pubbliche confrontate esattamente e width
derivate dal compilatore, ripetendo guard di contesto, shape, Γ e
tentativo; nessun Circuit viene trattenuto fra le PCS. Il conteggio
canonico di compilazioni passa analiticamente 4.293→1.908.

Sul Γ ammesso, il core coefficienti prima del primo round ottimizzato
contava 972.294.988.954.860 moltiplicazioni Fp3 per risposta. Il risparmio
esatto è 128.288.785.794.560 (13,19443% del solo core coefficienti),
con residuo 844.006.203.160.300 ancora CPU. I 998.927.195.904 callback
del checkpoint per risposta restano invariati. Non sono nuove
ricostruzioni A e non si presenta questo risparmio come riduzione
misurata del tempo completo o come accelerazione CUDA.

## Evidenze locali e ambiti

Sul source finale passano sette filtri separati: primo round Booleano,
packed replay con scale miste nonzero, cache/geometrie, metadati,
telemetria, preflight e nuova fixture GKR completa. Quest'ultima,
`c71_b12_packed_mixed_gkr_complete_wire_mac_and_endpoint`, usa 8 celle,
3 programmi e 2 depth; confronta packed e riferimento denso, verifica
wire esatto di 14.320 B, transcript/RNG, endpoint e MAC originali,
consuma tutte le 472 correlazioni di ciascun ruolo e rifiuta il MAC
alterato. Passa in 2,653 s con RSS 122.204.160 B. È GKR senza PCS:
il credito delle composizioni PCS precedenti rimane distinto; non
dimostra una prova canonica completa o una catena AES reale nuova.

Il benchmark packed usa programmi RMS con scale ponderate/non ponderate
nonzero, ma non Γ ammesso. A depth97/98 il replay letterale+row misura
311,183/310,918 ms, il packed+row 10,911/10,850 ms; costruzione del
plan separata 202,025/192,756 ms. Sono tempi CPU di un componente su
scratch riusato, non tempi H100, RMS pinned completo o inferenza.
La selezione packed non estende l'ammissione numerica di Γ.

La nuova build mirata O0/64 codegen unit, un job e LLD un thread passa
in 55,615 s con RSS aggregato campionato 2.607.816.704 B. Deadline
120 s e Stop del RSS aggregato a 3 GiB riguardano soltanto la build;
lo stop non è stato attivato. I test restano AS 2 GiB/60 s e un thread.
Il cambio risponde al costo e ai retry osservati sulla VM: il vecchio
limite build60 non derivava dal protocollo. I vecchi timeout di build
restano immutabili, con le proprie SHA e provenienza.

I timeout del test c0 reale e mixed421 con PCS a 60 s sono negativi,
non vengono riprovati con cap esteso. Restano distinti anche timeout
KV/AES e uncached già conservati nei checkpoint precedenti. Positivi
ridotti, profili analitici e nomi dei filtri non convertono questi
esiti in pass né completamento canonico.

## Capacità e lifetime

Il conto finale include tutte le 11 classi e i lifetime selezionati;
massimo 5.878.734.834 B, residuo 26.845.198 B sul
payload 5.905.580.032 B. `joint_admitted:false` e riserva fisica non
verificata conservano il confine rispetto alla H100. Path/argv ≤4.096 B
e identità Γ/layout/toolchain sono premesse esplicite del manifest.

Sei profili misurano 49.104.156 B, aumento effettivo di 672 B rispetto
al precedente census; non il +288 B inizialmente previsto. La fixture
metadata-only tiene la cache privata a None: i due Vec production
aggiungono separatamente un upper pinned di 58.176 B. Il packed replay
ha upper RMS-only di 387.537.052 B, inclusi stato prefisso/Option e
32 B aggiuntivi; i record con old+new durante crescita sono
6.144×176 =1.081.344 B. Questi temporanei muoiono prima delle query PCS,
perciò non si sommano ai loro picchi. Il record distingue capacità
misurate, upper da sorgente e allowance fisica da misurare.

## Chiusura e campagna successiva

Il goal di preparazione locale è concluso con i PASS finali,
la verifica del ledger e l'aggiornamento coordinato dei cinque documenti
attivi. Non richiede la nuova campagna H100 e non
afferma che i target hardware siano raggiunti. Nessuna nuova campagna
è autorizzata: hardware e durata richiedono una nuova decisione.

PCS/S1/query W sono integrati; i limiti rimasti sono misure fisiche e
costi residui espliciti. La campagna dovrà riusare Γ dopo verifica
delle identità, ripetere parità CPU/CUDA, controllare NoPeek e letture
causali, misurare memoria congiunta/allowance e i cinque tempi separati:
installazione, setup, inferenza, prova, verifica. Dovrà profilare
producer, FFT/hash/sali, aperture, RMS/GKR/range, sincronizzazioni e
core coefficienti CPU; confrontare W ordinario/Tensor e QK/PV solo con
parità e tempi rappresentativi. TMA, fusioni e CUDA Graphs sono opzioni
da misurare, non benefici attribuiti al checkpoint locale.
