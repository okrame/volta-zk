# C7.1 — cattura A di componente con overhead ridotto

Il trial pulito `canonical-profile05`, codice `76a9201d`, termina prima
del primo gruppo A completo: fisico campionato 6.715.858.432 B contro
6.174.015.488 B. W/installazione e setup AES terminano; cattura 113–117
non raggiunta. Il grafico allocazioni Nsight è attivo nel launcher anche
prima di `start`; non attribuiamo a esso tutti i byte aggiuntivi. Launcher
e agenti sono fermati, GPU rilasciata, otto identità discendenti contate.
Il negativo resta conservato; nessun altro setup completo viene ripetuto.

Nuova ipotesi di misura: un breve caller `commitment-a-cuda`, senza PCS W
e setup AES, disattiva `--cuda-memory-usage` per ridurre il costo della
strumentazione. L’help installato 2025.1.1 segnala overhead significativo
del grafico; non offre un bound. [Controller](../../scripts/c71_profile_window.py)
con flag esplicito `--no-cuda-memory-usage`, default invariato, mantiene
API/kernel/correlation CUDA. Finestra dopo 1 fino a 3 gruppi completi,
trace owner da gruppo 2, geometria originale 512, journal/sessione nuovi.

Stessi cap payload/fisico, deadline, monitor subreaper e stop. Una timeline
valida fornisce solo attribuzione di componente; mancano grafico
allocazioni, presenza congiunta W/setup e finestra dello spike storico.
Se il costo resta eccessivo, si conserva il negativo e si passa ai caller
non strumentati. Nessun aumento di cap o credito di prova/verifica.
