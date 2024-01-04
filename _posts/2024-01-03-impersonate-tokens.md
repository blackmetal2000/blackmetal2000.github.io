---
title: "Token Impersonation: uma abordagem mais interna."
date: 2024-01-03 00:00:00 +0800
categories: [Windows, Tokens]
tags: [Red Team]
---

![Desktop View](https://i.imgur.com/xzmWmIJ.png){: width="672" height="289" .w-50 .left}
Durante o período de pós-exploração, o invasor na maioria das vezes busca o maior nível de privilégio na rede.

No contexto de Active Directory, esse nível de privilégio é, por muitas vezes, conferidas ao Administrador de Domínio, onde o atacante almeja este acesso. E os inúmeros vetores de ataques no Windows contribuem para isso.

Hoje, vamos nos aprofundar numa técnica interessante de elevação de privilégio e que já me rendeu acesso de domain admin: *Token Impersonation*.
