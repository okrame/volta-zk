# RMS misto: correzione della diagnosi e censimento pubblico — 11 ottobre 2026

Il [record pulito `dc0064d7`](../../benchmarks/results/c71-certificates-rms-moments-census-2026-10-11-dc0064d7.json)
conserva il secondo esito wire negativo e il censimento concluso alle
18:10:06 UTC sullo stesso pod/H100. Corregge la diagnosi del
[primo record](../../benchmarks/results/c71-certificates-rms-moments-rust-negative-2026-10-11-b459b8f6.json),
che rimane immutabile insieme al suo binario e ai log.

## Diagnosi corretta della fixture

Entrambi i fallimenti avvengono nel caso `fault == 0`, etichettato onesto.
Sei celle del programma1 hanno il predicato Booleano uguale a zero:
prodotti204 nelle celle3/7/11 e76 nelle celle21/25/29. La formula della
fixture usa12, ponendo entrambi i bit del gate AND a uno; usare4 conserva
un bit solo e rende vero il predicato composto. La correzione aggiunge
assertion sul replay letterale `Circuit::replay` prima della prova,
incluse le due alterazioni che devono rispettivamente violare il predicato
e conservare il predicato cambiando i byte PCS. **Riverifica pendente.**

Il marker wire/FS/MAC uguale nei due fallimenti non prova acceptance:
entrambi i prover costruiscono la stessa wire su input non valido.
La prima attribuzione al caso negativo era errata. Nessuna regola del
verifier originale è modificata o aggirata.

## Censimento e costo condizionale

Il replay parallel CPU coincide con il replay layered Booleano originale
per159 programmi e99 profondità su tre pattern/maschere di liveness.
I [sei log pubblici e lo screen](../../benchmarks/results/c71-certificates-rms-moments-census-2026-10-11-dc0064d7)
conservano gate per programma, operazioni, slot, piani e provenance.
Il massimo shared per CTA è40.896B, inferiore al limite opt-in H100
232.448B letto dal driver; nessuna esecuzione o parità CUDA dedotta.

La schedule prefix4, batch4096, chunk32 riusa una stage originale fra
tutti i chunk e riduce/pesa ogni batch. Massimo nuovo payload nominato
130.378.444B alla profondità48, esclusi caller comune, costruzione dei
piani/allocator, tail fold/core, indici/byte/PCS e residenza fisica.
Totali sulle99 profondità:

- 34.445.765.376 frame originali e197.209.352.886.976 operazioni packed;
- 20.053.914.957.312 istruzioni BMMA warp e975.756.751.472 prodotti Fp3 di pesatura;
- 203.513.744.925.696 termini shift/add e24.443.818.538.631.168B di letture/scritture logiche dei contatori.

L'ultimo conto non misura HBM o throughput. La schedule è `credit:false`,
`complete_capacity:false`, `complete_work:false`, `joint_admitted:false`.
Il piccolo buffer non risolve il traffico: esaminare una riduzione fusa
prima di implementare o provare questo consumer su dominio canonico.
Resta inoltre il tail originale:180.614.781.721.340 prodotti Fp3 dopo
i primi quattro round, escluso il lavoro del nuovo prefisso.

## Verifiche, risorse e conservazione

Build451,634s; coefficienti Goldilocks passati; test wire exit101/3,204s.
Due test dello screen, tre Python prefix e nove documentali passano.
I sei blocchi del censimento e lo screen passano separatamente dopo il
fallimento del launcher composto; non ne riscrivono il terminale.
AS CPU64GiB, un job/worker, cap fisico6.174.015.488B e scadenze originali.
Durante la build due campioni GPU4MiB coincidono con l'interrogazione
degli attributi driver; nessuna attribuzione a un kernel o isolamento.

Bundle privato `artifact/c7.1-pod/certificates-rms-moments04-rust02-20261011`:
134file/44.399.960B, manifest SHA256
`e8e82297843a95d88456dee7f1d81bdd957da1f33800ca18e71e600ea3b3881b`.
Binario36.678.960B, SHA256
`683f018209741768e892eaa83b6d2ebbae436caee9110ad2f4bec33649c61c5d`.
Record SHA256
`62033f3e542b2b3ff1d7876e4c04fb565bfe2b69458f7109edaa29734c63c5b0`.
Ogni file del bundle è riverificato; originali e primo negativo preservati.

Pod e guard restano attivi; VM solo editing/controllo. Termine calcolo
23:43:00 e hard stop12 ottobre00:13:00 UTC invariati dal riavvio.
Nessun nuovo setup AES o runner canonico; zero certificati, O=0 incompleto.
Distributività, corrispondenza selector/mask/wire, determinismo dei frame,
lifetime/capacità e raffinamento CUDA restano premesse non scaricate.
