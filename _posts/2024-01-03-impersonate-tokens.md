---
title: "Token Impersonation: uma abordagem mais interna."
date: 2024-01-03 00:00:00 +0800
categories: [Windows, Tokens]
tags: [Red Team]
---

Durante o período de pós-exploração, o invasor na maioria das vezes busca o maior nível de privilégio na rede. No contexto de Active Directory, esse nível de privilégio é, por muitas vezes, conferidas ao Administrador de Domínio, onde o atacante almeja este acesso. E os inúmeros vetores de ataques no Windows contribuem para isso.

Hoje, vamos conferir uma abordagem mais interna num vetor de ataque bastante interessante e que já me rendeu uma elevação de privilégio ao domain admin: **Token Impersonation**.

![Desktop View](https://i.imgur.com/xzmWmIJ.png){: width="350" height="250" }
