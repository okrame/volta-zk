# C7.1 — archivio e provenienza

Per il lavoro corrente leggere [design](../c7.1/design.md), [specifiche](../c7.1/specs.md),
[sicurezza](../c7.1/security.md), [test locali](../c7.1/local-tests.md) e
[test su RunPod](../c7.1/runpod-tests.md). Le istruzioni di questo archivio
valgono soltanto per il checkpoint che descrivono.

Le esplorazioni successive alla chiusura H100 sono nella
[chiusura locale del 10 ottobre](local-exploration-close-2026-10-10.md),
con [baseline/inventario](local-baseline-exploration-2026-10-10.md),
[esecutore](local-executor-2026-10-10.md),
[screening Γ/RMS](gamma-screen-2026-10-10.md) e
[piano hardware](local-hardware-plan-2026-10-10.md).
Il [seguito locale](local-followup-2026-10-10.md) conserva padding zero,
traccia owner/clock, predicato RMS/replay/supporti ridotti, upper packed e
le nuove domande hardware; non esegue una nuova campagna.

## Percorsi di lettura

- [Decisioni](decisions.md): successione delle scelte, esclusioni e motivazioni.
- [Evidenze](evidence.md): controlli eseguiti e collegamenti ai record immutabili.
- [Stato precedente](status.md) e [design precedente](design.md): quadro cumulativo prima della riorganizzazione.
- [Analisi delle risorse](preflight.md), [confronti di costruzioni](construction-screen.md)
  e [PCS e stato](pcs-state-screen.md): alternative, limiti e controesempi.
- [Piano di calibrazione precedente](c71-calibration.md): proposta originale;
  la procedura operativa è ora in [runpod-tests](../c7.1/runpod-tests.md).
- [Catalogo dei test precedente](build-and-test.md): include esperimenti non selezionati.
  Per i test correnti usare [local-tests](../c7.1/local-tests.md).

## Campagne recenti e decisioni operative

- [Inferenze reali del seguito](h100-followup-inference-2026-10-10.md): parità dei token e pool isolato, senza credito di prova.
- [Limite della cattura Nsight](h100-profiler-limit-2026-10-10.md): due stop fisici prima di A, timeline dello spike ancora aperta.
- [Default canonico del seguito](h100-followup-default-2026-10-10.md): 116 gruppi A completi, step GPU 511 MiB e stop fisico.
- [Avvio del seguito H100](h100-followup-start-2026-10-10.md): nuova autorizzazione e deadline del pod già attivo.
- [Prefisso canonico del seguito](h100-followup-spike-prefix-2026-10-10.md): W/setup e 35 gruppi A; saturazione del logger, clock ridotto verificato.
- [Metodo del confronto d'inferenza](h100-comparison-plan-2026-10-10.md): workload, due precisioni e criteri fissati prima delle misure.
- [Ultimo diagnostico H100 terminale](h100-a-blocking-terminal-2026-10-10.md): stop fisico anche con lanci sincroni, dopo 86 gruppi A.
- [Chiusura campagna H100](h100-campaign-close-2026-10-10.md): spegnimento confermato, misure separate, guadagni e limiti residui.
- [Code ridotte e diagnostico A](h100-a-quarter-2026-10-10.md): A03 supera il cap, parità sincrona 15/15 prima dell’ultimo diagnostico.
- [Sesto trial H100 terminale](h100-canonical-06-2026-10-10.md): stop fisico dopo 35 gruppi A e diagnosi ancora aperta.
- [W e setup del sesto trial H100](h100-setup06-checkpoint-2026-10-10.md): tempi completi, confronto cGGM e limiti della misura.
- [Parità H100 del prefisso originale](h100-prefix-validation-2026-10-10.md): libreria sm_90 e 15 test reali con capacità KV parzialmente inizializzata.
- [Avanzamento A dopo la correzione](h100-a-prefix-progress-2026-10-10.md): tre gruppi diagnostici, stop pianificato e nuova sessione canonica.
- [Componenti del 9 ottobre](crypto-components-2026-10-09.md): scan lineare, XOF pinned, confronto Tensor e correzione causale QK/PV, senza campagna.
- [Consumer PCS A residente dell'8 ottobre](crypto-a-source-2026-10-08.md): codec, quattro coset, FFT/hash, risorse e limiti del componente locale.
- [Evidenze del consumer A](crypto-a-source-evidence-2026-10-08.md): record pulito e regressioni dell'owner/Tree W, senza integrazione A o campagna.
- [Decisioni dell'8 ottobre 2026](operating-rules-2026-10-08.md): nuova autorità operativa, ritenzione e geometrie ottimizzabili.
- [Ritenzione degli artefatti](artifact-retention-2026-10-08.md): inventario verificato e rimozioni autorizzate.
- [Runbook alla chiusura del 7 ottobre](runpod-tests-2026-10-07.md) e [design dello stesso checkpoint](design-2026-10-07.md): cronache, stime e autorizzazioni storiche; non istruzioni per nuove campagne.

## Conservazione e mappa dei percorsi

Origine della migrazione: commit `5b293bc9f9b976ba4b6fc9e6a612fdbaf42b6fdb`. I file qui archiviati mantengono
il contenuto tecnico originario; nei documenti non congelati cambiano solo
la navigazione e l'avvertenza iniziale. I tre documenti indicati come copie
esatte conservano ogni byte, compresi i vecchi riferimenti relativi: interpretarli
rispetto al percorso originale nella tabella, quindi applicare questa mappa.
La navigazione moderna verso questi documenti usa i link della tabella.
I digest seguenti identificano gli originali, non le edizioni con link aggiornati.
Benchmark, fonti in `sota` e milestone formali non sono modificati.

| Percorso originale | Archivio | Conservazione | SHA-256 originale | SHA-256 senza destinazioni dei link |
|---|---|---|---|---|
| `docs/c7.1-attention-products.md` | [c7.1-attention-products.md](c7.1-attention-products.md) | solo navigazione aggiornata | `a2c82b0be237a522269e86c921f15325d3fe300202a7ffb13033b3e7c9323073` | `65d4c1e0c020b9c12ef95046ce18582e3d7a357e5309c6bdea484e65b8851596` |
| `docs/c7.1-auxiliary-witness.md` | [c7.1-auxiliary-witness.md](c7.1-auxiliary-witness.md) | solo navigazione aggiornata | `0494461f3a2e8b902e3fbab3927f3f5c4c4ed23e5d9944c57498ec03b8e1ab38` | `798fbd3cc46081caca64adc7b4331b063ecd7a5b3133c15f135e0c42462ea929` |
| `docs/c7.1-committed-mac-opening.md` | [c7.1-committed-mac-opening.md](c7.1-committed-mac-opening.md) | solo navigazione aggiornata | `f018ea954ad991abfad1e81915402d8b1705ad54042530119fe20b7ee9824c8a` | `cd32bb8b7cbc4ae911edcb01852dce34cebfd7b9c4f5f3bb1be6c71de24768e9` |
| `docs/c7.1-cut-witness.md` | [c7.1-cut-witness.md](c7.1-cut-witness.md) | solo navigazione aggiornata | `8162502d2aa0b2ced7f5d58669921f31880accff645d934451dbbbd61885f110` | `4b9084a1e223dbcfb2ad01dfc6a777bc937262e605544e23f8e03eaca654edc3` |
| `docs/c7.1-feasibility.md` | [c7.1-feasibility.md](c7.1-feasibility.md) | solo navigazione aggiornata | `898950b132da518834ec80daf168bbff15251424b527fd9b9ff323645a952919` | `d83f748f17cda30a76147a5af4c5e16f562291470dc71e715f996cf2fbf76660` |
| `docs/c7.1-fixed-run-composition.md` | [c7.1-fixed-run-composition.md](c7.1-fixed-run-composition.md) | solo navigazione aggiornata | `2ea619e06f6a46f75f21ab9c6a71de7e521b8171631727b00365cf538fbe1771` | `6bfa7b5c114c66f06722d83a07df70787e614ddadc2b6d4895ed39d12b225317` |
| `docs/c7.1-gemma31b-design.md` | [c7.1-gemma31b-design.md](c7.1-gemma31b-design.md) | copia esatta | `98d1d0feb1927929878f3fdd47c6f2c2a51616255ecace4e0cacb08b24b78f82` | `ed43c22f81445f12d413294fa50af3b0b64cfac1303ab364c06e57b653f6c3ae` |
| `docs/c7.1-kv-transition.md` | [c7.1-kv-transition.md](c7.1-kv-transition.md) | solo navigazione aggiornata | `8ef7904266f10b82db50c224ddb42fb077dfbb50d98de60f5a5c7e3aba408ff2` | `8dd64ad2e1296887650df17da4336ec119e3b1661a728bb3021fedef7235f7ac` |
| `docs/c7.1-paired-rs-opening.md` | [c7.1-paired-rs-opening.md](c7.1-paired-rs-opening.md) | solo navigazione aggiornata | `14e303dc056eb5e06d981b2c86b3549f1b13e8482c7ad6af5d69fc502a5c153f` | `a8aff2b5ae0ad5c416ee21e12f6159563c0545a9cda9c3283a66bef69e6d0f98` |
| `docs/c7.1-recursive-rs-opening.md` | [c7.1-recursive-rs-opening.md](c7.1-recursive-rs-opening.md) | solo navigazione aggiornata | `d709abcb342b8fdc8645e5a532023459c9039e8028462edadc334a39ada2211d` | `49bceda4d3a2e7d64647a6068cc09d4abce9aca7625c41c590efa31db8eb21f0` |
| `docs/c7.1-requantization.md` | [c7.1-requantization.md](c7.1-requantization.md) | solo navigazione aggiornata | `4c4cc1975bf32698cac84663e17d9d5ece40782253960019fbc93be13fb171fc` | `29c4e6c3f1bdd2d1a259af63b524c97c85a47a728a07f1e32f8716e4fd2b26a3` |
| `docs/c7.1-rne-indicators.md` | [c7.1-rne-indicators.md](c7.1-rne-indicators.md) | solo navigazione aggiornata | `f433ec9173f392b65bbf8216f6926ab1ea539237b9203f55bec6f233927ceb0d` | `6a8113e26065e9ac022d635fee72072edcf8451295c4ff1ad369d323e895a7fe` |
| `docs/c7.1-wide-hash-opening.md` | [c7.1-wide-hash-opening.md](c7.1-wide-hash-opening.md) | solo navigazione aggiornata | `f1f61d5046d18dd07bb57eac6276eba5ba8e159370cbfa370c0d8a10ac03699a` | `bfac3521bae5e9c00014fd03f9e76201fac400a643bfe9ffc3b4397672e8b9ba` |
| `docs/c7.1/construction-screen.md` | [construction-screen.md](construction-screen.md) | solo navigazione aggiornata | `f5cfdf1fb9f14ac3e205bc43145d703acc0a752cc28de1423c0b8b2970559aea` | `05eed7884e21e76cf255119ea0d77c7d156c4616066dab45a209cc91837d7d32` |
| `docs/c7.1/decisions.md` | [decisions.md](decisions.md) | solo navigazione aggiornata | `4eca3c98a7a07d026765791075185046c82e7357f720b3eb1711e35f7e14c9d1` | `f081adc0c77e475a5e24c417b6c518cd94e79cf360426d241b97b13d4c22007f` |
| `docs/c7.1/design.md` | [design.md](design.md) | solo navigazione aggiornata | `6945ccc6462a071f6faa73da10e2d18c97905056adceb8b50b3030bc0723e034` | `611dd0ea5b83e48c0215e6fb751697036640db0a36410728cfbcf23b1cd9f1f0` |
| `docs/c7.1/evidence.md` | [evidence.md](evidence.md) | solo navigazione aggiornata | `b2e45073b861bc13ddc136b9330289326bcf0289626bc55215d83b91de2da8aa` | `755bd19ff6e03107b56606a0c2fdae21dbbe66299f372415c013fd7999404efe` |
| `docs/c7.1/pcs-state-screen.md` | [pcs-state-screen.md](pcs-state-screen.md) | solo navigazione aggiornata | `163e6f58464c9a9cfd6aa150ca93673088d7db640a179ad8e4b08b4d96f7b2ef` | `1f69430afc3efa285d4cdf2656b3948d5b7cf0a4d037394b8b394c297eac124a` |
| `docs/c7.1/preflight.md` | [preflight.md](preflight.md) | solo navigazione aggiornata | `0bbbcb1a37b3d02abb021992e558cd12fb294a7013f7cd4892c73f4c78b7129d` | `8106829e1069d50b16e45e82d11c545d220dc81ca92f2fe35fd3afd853655d86` |
| `docs/c7.1/security.md` | [security.md](security.md) | solo navigazione aggiornata | `3bef620cc96f184e18ab3a94a9efffcb43d5d83ac7c46b086e33ea363c704871` | `73c0d9cd0f12a4354a449a80c6c7a6718b7656a7039120895e55dbaf81c56fed` |
| `docs/c7.1/status.md` | [status.md](status.md) | solo navigazione aggiornata | `ee487cd59f93bf1e3df66dea2272b9aec0cf8b1b5bf7ad1e1ae3cedd01110a8d` | `ca2f48a03b0522dfab8cecb35273256c20ff1a9dfa2790977fc64d2eaccb18af` |
| `docs/procedures/build-and-test.md` | [build-and-test.md](build-and-test.md) | solo navigazione aggiornata | `a57fb6a7014f9d2b6a753e14d5d7fcf8178c7143f5145bced0bc93947d98bb2f` | `7b174bf10c020b4968410eec2ee717ae3e347279280ce1d638e0d4961b588d6c` |
| `docs/procedures/c71-calibration.md` | [c71-calibration.md](c71-calibration.md) | solo navigazione aggiornata | `311951ef4a511f3883b07ddf81283809ae315a5c5f50d39ba05a9d82e8ce1ae0` | `050a8ff80234ccee5e0f26a70c2d8313f55a0ace280b4fc99b881a267506638c` |
| `docs/procedures/runpod.md` | [runpod.md](runpod.md) | solo navigazione aggiornata | `02a08cd77c7a1ec51334a205aba4c314a54be1b95e7cc7597d51f02f589dddda` | `bd19e20c795f386ed5e039bb66cd0b98dd328d3bf4a67940d352cacfb0e0bbda` |
| `docs/prototype-status-history-2026-09-07.md` | [prototype-status-history-2026-09-07.md](prototype-status-history-2026-09-07.md) | copia esatta | `5dc3bfcf06edc66250741737fb9ac4d2a1b5b650cc607d2dce1ed21968343bb8` | `2ae1a8f375e7ec899690acba12b99f71f902cdf543764509240f9601e1b0b7ca` |
| `docs/prototype-status-history-2026-09-10.md` | [prototype-status-history-2026-09-10.md](prototype-status-history-2026-09-10.md) | copia esatta | `ee535a27757b8796357c54258438e4186eaf1f9c1248d4fa80f22e7b58e3cf03` | `9be6d2c23b0f51a09c5aaa8155de1cb1a7f102d6c8ad64190c32e35500bfb496` |
| `docs/prototype-status.md` | [prototype-status.md](prototype-status.md) | solo navigazione aggiornata | `fb54cd257daf9560ea67db9bfdf5b05385f42c33cb2a281acf3c9be380bffc40` | `6001d43dac0c70c583f541d315dfdf74b76088cb270a3421bf648891faf90555` |

- [Tree PCS A, sali strided e candidata limb16](crypto-a-tree-2026-10-08.md).

- [H100: coda SHAKE cGGM differita, 9 ottobre 2026](h100-cggm-tail-2026-10-09.md).

- [H100: quinto trial canonico, 9 ottobre 2026](h100-canonical-05-2026-10-09.md).

- [H100: diagnostico A, 10 ottobre 2026](h100-a-diagnostic-2026-10-10.md).

- [H100: candidata sul prefisso KV, 10 ottobre 2026](h100-prefix-candidate-2026-10-10.md).
