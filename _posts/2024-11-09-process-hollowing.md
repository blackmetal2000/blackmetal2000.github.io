---
title: "Process Hollowing: uma análise interna."
date: 2024-11-09 00:00:00 +0800
categories: [Windows, Process Injection, Shellcode]
tags: [Red Team]
---

![Desktop View](https://i.imgur.com/XzUPqOm.jpeg){: width="400" height="400" }

O Windows não deixa a desejar quando o assunto é Process Injection. Diferentes técnicas de injeção de shellcodes em processos locais/remotos são descobertas e publicadas para pesquisa. Dentre elas, uma que me chamou bastante atenção, e que é o assunto que abordaremos hoje, é a técnica de **Process Hollowing**!

Neste artigo, buscaremos responder as seguintes perguntas:

- O que é Process Injection?
- Qual o seu impacto?
- O que está ocorrendo por de trás dos panos?

O interessante dessa técnica é que ela vai além do funcionamento básico de uma injeção de shellcode. Em vez de apenas alocar memória no processo remoto e inserir o shellcode, exploraremos a estrutura fundamental de um executável PE para abusarmos de atributos importantes para a execução do nosso shellcode.

## Introdução

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
