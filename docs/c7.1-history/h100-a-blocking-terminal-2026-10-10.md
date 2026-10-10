# H100: anche il diagnostico sincrono supera il cap — 10 ottobre 2026

Il [quarto componente A](../../benchmarks/results/c71-h100-a-component04-2026-10-10-47af19bbe888.json)
termina alle **01:45:07 UTC**, dopo **780,205 s**, exit −9. Il monitor
rileva **6.535.814.656 B** temporanei fisici contro 6.174.015.488 B:
**361.799.168 B oltre cap**. È uno stop fisico, prima del timeout diagnostico.
Tutti i **3.898 campioni** sono stabili, senza errori smaps o swap.
Il payload massimo dichiarato, 5.554.398.549 B, resta sotto 5.905.580.032 B.

Caricamento W **64,110 s**, residenza CUDA **22,510 s**, preparazione
con inferenza **88,335 s**. L'ultimo avanzamento A è a **588,211 s**,
**86/512 gruppi**, 1.141.742.799.768 visite sorgente. A non termina.
Nessun W commitment, setup AES, prova MAC, verifica, certificato o
continuazione è rappresentato da questo componente. Il monitor usa
SIGKILL: non è una ricevuta di cleanup dell'owner.

I due campioni terminali hanno RSS host 61.606.055.936 B ed esenzioni W
identici. La GPU passa da 67.185.410.048 a 67.719.135.232 B:
**+533.725.184 B (509 MiB)**. Il controllo successivo trova zero processi
compute e GPU libera. Non identifica la causa dello spike durante il run.
Anche `CUDA_LAUNCH_BLOCKING=1` con code `0.25x`, compute/copy 1/1 e
stack 256 B **non risolve** il superamento. Il numero maggiore di gruppi
prima dello stop non è un miglioramento di risorse dimostrato.

La [parità reale preliminare](../../benchmarks/results/c71-h100-blocking-parity-2026-10-10-47af19bbe888.json)
passa 15/15 più controllo non lineare. Sorgente pulita `47af19bbe888`,
Rust `3ea1e4a` compatibile e libreria prefix invariati; stessi Γ, W packed
sigillato, geometria D34, 512 ricostruzioni e cap. Monete PCS nuove dopo
NoPeek; nessuna correlazione usata. Nessun parametro di protocollo,
semantica o MAC è cambiato. Lanci sincroni rimangono diagnostici.

Questo è l'ultimo run della campagna: si conserva il fallimento, senza
ulteriori tentativi o estensioni, e si procede alla chiusura con stop
provider confermato. La sola inferenza selezionata supera già il target
65 s; i timeout diagnostici lunghi non lo modificano. Il percorso canonico
resta a zero certificati e O=150/300 non iniziati.

Bundle `h100-final-a-component04-20261010T014643Z`: 15 file/1.626.988 B,
manifest SHA-256 `bfec22949a4a5a8a5b8fc2b9c932d660ddc113e6161324dc17c9c62901b21b85`.
Hash verificati dopo il trasferimento, manifest e precedenti fallimenti
immutati. La chiusura provider avrà una ricevuta separata.
