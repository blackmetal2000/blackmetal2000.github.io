---
title: "LSASS: A reciclagem também está presente nos handles."
date: 2023-06-03 00:00:00 +0800
categories: [Windows]
tags: [Red Team]
---


Como sabemos, o processo do LSASS é um tesouro quando se observado pelo lado ofensivo. É neste processo que informações de logons de usuários são armazenados (como as valiosas NT hashes). Quando o assunto é dump de credenciais, um handle com permissões de `PROCESS_VM_READ¹` ao LSASS se torna tudo o que um atacante quer.

![Desktop View](https://pbs.twimg.com/media/GCKPn8UXsAAHl-B.jpg){: width="100" height="50" }

> `PROCESS_VM_READ¹`: permissão necessária para a leitura da memória (dump) de um processo. 
{: .prompt-info }

Contextualizando: durante meus estudos de Windows API, estive aprofundando em técnicas de dump de LSASS que normalmente um EDR/XDR não detectaria. Em um laboratório, instalei um famoso antivírus do mercado (no qual não citarei o nome) e que me rendeu bastante trabalho. Quando eu abria um handle pro LSASS e tentava interagí-lo, um erro era retornado: STATUS_ACCESS_DENIED.

![Desktop View](https://i.imgur.com/RBZ4JSv.png)
