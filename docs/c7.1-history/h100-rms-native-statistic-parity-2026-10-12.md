# H100 — statistica originale e caller ridotto verificati

Checkout pulito539de600, GPU51da64b4 della campagna di sei ore.
[Record](../../benchmarks/results/c71-certificates-rms-native-statistic-2026-10-12-539de600.json)
SHA2569a9e30609cdb04f0dbba77d31bcf5369a226a1e11d82d1301482ea0a19a9abc2.
130 file chiusi, archivio14.033.652 B, tutti gli hash verificati nel bundle
privato. Il negativo precedente resta immutabile.

Passano14 check: build Rust, simboli mancanti/owner, callback fallibili P0,
P0/statistica originali, API byte e regressioni RMS/lineare, binding/live,
wire misto, due nuove GPU, produzione e9 documentali. CUDA17 sorgenti e
sette check owner (25 rifiuti statistica) riusati da9d37e8ae con identità
sorgenti C++/CUDA: è cambiato soltanto il costruttore della fixture Rust.

GPU statistica:1×1,3×5,129×1537, signed i16 estremi/ragged e query/challenge
zero/uno;24 cubic coefs e3 terminali densi originali, checkpoint massimo1.
Wire/FS/MAC ed endpoint uguali al prover CPU, verificatore originale passa,
S+1 respinto. Test1,58 s; monitor1,827 s: componente, nessuna extrapolazione.

Caller28 celle/93 profondità con statistica+byte nativi: wire/FS/MAC uguali,
RMS/PCS/P0/RNE/W/A originali accettano caso onesto e respingono due
alterazioni. Per caso1.271 allocazioni/rilasci,8.988 launch, arena massima
18.196.736 B, owner42.504 B, arena finale0, cleanup senza errore. Monitor
24,352 s; correlazioni ideali. Nessun modello/AES/risposta canonica qui.
Download/ingest CPU del modello concorrenti: nessun isolamento o picco
fisico completo inferito.

L’integrazione con owner condiviso è nel commit successivo16d60d38 e ha
un nuovo test con getter `try_lock`; il suo preflight è ancora in corso.
Zero certificati. Premesse Eq/fold/codec/immutabilità/lifetime e allowance
fisica aperte; stesso cap e compute end13:19:04 UTC, VM solo controllo.
