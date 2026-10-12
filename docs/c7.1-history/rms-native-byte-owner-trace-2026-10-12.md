# RMS byte GPU — owner host positivo e trace da aggiornare

Il [trial pulito fca43aef](../../benchmarks/results/c71-certificates-rms-native-byte-owner-trace-negative-2026-10-12-fca43aef.json)
passa owner byte (otto layer,30 rifiuti), indici e quattro controlli
owner generici con g++/UBSan/Werror. Owner ordinario42.504B confermato
dal fixture, cleanup/allocazioni e sorgente bloccata verificati.
Sono controlli con driver simulato, nessun credito di aritmetica GPU.

Trace termina con due failure e due pass: le aspettative Python
42.536/42.528B erano rimaste vecchie. Il context nuovo misura
42.544B nella build physical e42.536B con trace ordinaria, cioè
42.504B più40/32B. La correzione aggiorna solo queste aspettative;
accounting runtime e check del fixture basato su sizeof erano corretti.
Negativo e positivi preservati in un nuovo archivio/manifest con hash.

Byte host15,210s, fisico campionato392.306.688B; indici14,409s;
owner44,621s. Trace59,028s, fisico397.295.616B. GPU0 e nessun campione
incompleto in questi quattro check, senza credito al picco istantaneo.
Nuova verifica trace e verifiche CUDA/Rust/coefficienti/terminali/wire/caller
restano pendenti sul pod autorizzato. VM solo editing/controllo/hash,
finestra compute13:19:04/guard13:39:04/deadline13:49:04 UTC invariata.
Zero certificati canonici; O=0/journal e O=150/300 incompleti.
