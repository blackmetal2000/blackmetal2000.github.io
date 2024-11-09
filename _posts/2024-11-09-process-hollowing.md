---
title: "Process Hollowing: uma análise interna."
date: 2024-11-09 00:00:00 +0800
categories: [Windows, Process Injection, Shellcode]
tags: [Red Team]
---

![Desktop View](https://i.imgur.com/SqTJ0g4.jpeg){: width="300" height="300" }
![Desktop View](https://i.imgur.com/XzUPqOm.jpeg){: width="300" height="300" }

O Windows não economiza quando o assunto é vetores de ataque. As inúmeras maneiras de se executar um comando, de elevar privilégios, de persistências, se tornaram uma marca registrada do sistema.

Hoje, vamos nos aprofundar numa técnica de ataque que, particularmente, acho bem interessante: **Token Impersonation**.

Basicamente, o ataque consiste nas seguintes etapas:

- Abrir um handle ao token do processo;
- Duplicar este handle (token);
- Impersonificar o token referenciado pelo handle.

## OpenProcess

Primeiramente, é necessária a abertura de um handle ao processo alvo que queremos manipular o token.

```csharp
[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

static void Main(string[] args)
{
	IntPtr hProcess = OpenProcess(0x1000/*PROCESS_QUERY_LIMITED_INFORMATION*/, false, Convert.ToInt32(args[0]));

	Console.WriteLine(
		hProcess == IntPtr.Zero
		? $"OpenProcess ERROR: {Marshal.GetLastWin32Error()}"
		: $"OpenProcess SUCCESS: {hProcess}"
	);
}
```

>`PROCESS_QUERY_LIMITED_INFORMATION (0x1000)`: o nível de acesso que o handle terá. Esta é a permissão mínima necessária para manipular tokens de processos.
{: .prompt-info }

Note que foi aberto um handle ao processo. A variável que armazenará este handle é a `hProcess`, que utilizaremos posteriormente nas próximas APIs.
